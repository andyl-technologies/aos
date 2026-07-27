//! Regex builtins: `match`, `split`, `replaceStrings`, and pattern compilation.

use super::*;

impl TreeWalk {
    pub(super) fn eval_match_primop(
        &mut self,
        id: IrId,
        span: Span,
        pattern_id: IrId,
        string_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let pattern_span = self.node(pattern_id)?.span;
        let pattern = self.eval_node(pattern_id)?;
        let pattern = self.context_free_string_bytes(pattern_id, pattern_span, pattern, "match")?;
        let regex = self.compile_match_regex(pattern_id, pattern_span, &pattern)?;

        let string_span = self.node(string_id)?.span;
        let string = self.eval_node(string_id)?;
        let string = self.context_free_string_bytes(string_id, string_span, string, "match")?;

        self.eval_match_bytes(id, span, &regex, &string)
    }

    pub(super) fn eval_match_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        pattern: EvalPrimOpArg,
        string: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let pattern_value = self.force_value(pattern.id(), pattern.span(), pattern.value())?;
        let pattern_bytes =
            self.context_free_string_bytes(pattern.id(), pattern.span(), pattern_value, "match")?;
        let regex = self.compile_match_regex(pattern.id(), pattern.span(), &pattern_bytes)?;

        let string_value = self.force_value(string.id(), string.span(), string.value())?;
        let string_bytes =
            self.context_free_string_bytes(string.id(), string.span(), string_value, "match")?;

        self.eval_match_bytes(id, span, &regex, &string_bytes)
    }

    pub(super) fn eval_split_primop(
        &mut self,
        id: IrId,
        span: Span,
        pattern_id: IrId,
        string_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let pattern_span = self.node(pattern_id)?.span;
        let pattern = self.eval_node(pattern_id)?;
        let pattern = self.context_free_string_bytes(pattern_id, pattern_span, pattern, "split")?;
        let regex = self.compile_split_regex(pattern_id, pattern_span, &pattern)?;

        let string_span = self.node(string_id)?.span;
        let string = self.eval_node(string_id)?;
        let string = self.context_free_string_bytes(string_id, string_span, string, "split")?;

        self.eval_split_bytes(
            id,
            span,
            pattern_id,
            pattern_span,
            &pattern,
            &regex,
            &string,
        )
    }

    pub(super) fn eval_split_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        pattern: EvalPrimOpArg,
        string: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let pattern_value = self.force_value(pattern.id(), pattern.span(), pattern.value())?;
        let pattern_bytes =
            self.context_free_string_bytes(pattern.id(), pattern.span(), pattern_value, "split")?;
        let regex = self.compile_split_regex(pattern.id(), pattern.span(), &pattern_bytes)?;

        let string_value = self.force_value(string.id(), string.span(), string.value())?;
        let string_bytes =
            self.context_free_string_bytes(string.id(), string.span(), string_value, "split")?;

        self.eval_split_bytes(
            id,
            span,
            pattern.id(),
            pattern.span(),
            &pattern_bytes,
            &regex,
            &string_bytes,
        )
    }

    pub(super) fn eval_split_bytes(
        &mut self,
        id: IrId,
        span: Span,
        pattern_id: IrId,
        pattern_span: Span,
        pattern: &[u8],
        regex: &Regex,
        string: &[u8],
    ) -> Result<Value, TreeWalkError> {
        let matches =
            self.collect_split_matches(pattern_id, pattern_span, pattern, regex, string)?;
        let mut values = Vec::new();
        let mut previous_end = 0usize;

        for captures in &matches {
            self.push_split_string(
                id,
                span,
                &mut values,
                &string[previous_end..captures.range.start],
            )?;
            let value =
                self.with_transient_value_stack_roots(id, span, values.as_mut_slice(), |eval| {
                    eval.alloc_regex_capture_list(id, span, string, &captures.groups)
                })?;
            Self::push_list_value(id, span, &mut values, value)?;
            previous_end = captures.range.end;
        }

        self.push_split_string(id, span, &mut values, &string[previous_end..])?;
        self.alloc_tree_walk_list(id, span, NixList::new(values))
    }

    pub(super) fn collect_split_matches(
        &self,
        id: IrId,
        span: Span,
        pattern: &[u8],
        regex: &Regex,
        string: &[u8],
    ) -> Result<Vec<RegexCaptureMatch>, TreeWalkError> {
        let mut matches = Vec::new();
        let mut search_start = 0usize;

        while search_start <= string.len() {
            let Some(captures) = regex.captures_at(string, search_start) else {
                break;
            };
            let Some(matched) = captures.get(0) else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::RegexCompile {
                        id,
                        pattern: pattern.to_vec(),
                        message: "regular expression match did not include the full capture"
                            .to_owned(),
                    },
                    span,
                ));
            };
            let range = matched.range();
            let group_len = captures.len().saturating_sub(1);
            let mut groups = Vec::new();
            groups.try_reserve_exact(group_len).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed { id, len: group_len },
                    span,
                )
            })?;
            for capture in captures.iter().skip(1) {
                groups.push(capture.map(|capture| capture.range()));
            }

            let len = matches.len().checked_add(1).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
            matches.try_reserve_exact(1).map_err(|_| {
                TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
            })?;
            matches.push(RegexCaptureMatch {
                range: range.clone(),
                groups,
            });

            if range.start == range.end {
                if range.end == string.len() {
                    break;
                }
                search_start = range.end.saturating_add(1);
            } else {
                search_start = range.end;
            }
        }

        Ok(matches)
    }

    pub(super) fn push_split_string(
        &mut self,
        id: IrId,
        span: Span,
        values: &mut Vec<Value>,
        bytes: &[u8],
    ) -> Result<(), TreeWalkError> {
        let value =
            self.with_transient_value_stack_roots(id, span, values.as_mut_slice(), |eval| {
                eval.alloc_static_string(id, span, bytes)
            })?;
        Self::push_list_value(id, span, values, value)
    }

    pub(super) fn push_list_value(
        id: IrId,
        span: Span,
        values: &mut Vec<Value>,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let len = values.len().checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        values.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
        })?;
        values.push(value);
        Ok(())
    }

    pub(super) fn alloc_regex_capture_list(
        &mut self,
        id: IrId,
        span: Span,
        string: &[u8],
        captures: &[Option<std::ops::Range<usize>>],
    ) -> Result<Value, TreeWalkError> {
        let mut values = Vec::new();
        values.try_reserve_exact(captures.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: captures.len(),
                },
                span,
            )
        })?;
        for capture in captures {
            let value = if let Some(capture) = capture {
                self.with_transient_value_stack_roots(id, span, values.as_mut_slice(), |eval| {
                    eval.alloc_static_string(id, span, &string[capture.clone()])
                })?
            } else {
                Value::null()
            };
            values.push(value);
        }
        self.alloc_tree_walk_list(id, span, NixList::new(values))
    }

    pub(super) fn eval_match_bytes(
        &mut self,
        id: IrId,
        span: Span,
        regex: &Regex,
        string: &[u8],
    ) -> Result<Value, TreeWalkError> {
        let Some(captures) = regex.captures_iter(string).find(|captures| {
            captures
                .get(0)
                .is_some_and(|matched| matched.range() == (0..string.len()))
        }) else {
            return Ok(Value::null());
        };

        let capture_len = captures.len().saturating_sub(1);
        let mut values = Vec::new();
        values.try_reserve_exact(capture_len).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: capture_len,
                },
                span,
            )
        })?;
        for capture in captures.iter().skip(1) {
            let value = if let Some(capture) = capture {
                self.with_transient_value_stack_roots(id, span, values.as_mut_slice(), |eval| {
                    eval.alloc_static_string(id, span, capture.as_bytes())
                })?
            } else {
                Value::null()
            };
            values.push(value);
        }
        self.alloc_tree_walk_list(id, span, NixList::new(values))
    }

    pub(super) fn compile_split_regex(
        &self,
        id: IrId,
        span: Span,
        pattern: &[u8],
    ) -> Result<Regex, TreeWalkError> {
        self.compile_regex(id, span, pattern, false)
    }

    pub(super) fn compile_match_regex(
        &self,
        id: IrId,
        span: Span,
        pattern: &[u8],
    ) -> Result<Regex, TreeWalkError> {
        self.compile_regex(id, span, pattern, true)
    }

    pub(super) fn compile_regex(
        &self,
        id: IrId,
        span: Span,
        pattern: &[u8],
        anchored: bool,
    ) -> Result<Regex, TreeWalkError> {
        if pattern.is_empty() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::RegexCompile {
                    id,
                    pattern: Vec::new(),
                    message: "empty regular expression".to_owned(),
                },
                span,
            ));
        }
        self.validate_match_regex_pattern(id, span, pattern)?;
        // Re-emit POSIX ERE bracket expressions in Rust `regex` syntax; the
        // two grammars diverge inside `[...]` (see `eval_regex_ere`).
        let translated = translate_posix_ere(pattern).map_err(|message| {
            TreeWalkError::new(
                TreeWalkErrorKind::RegexCompile {
                    id,
                    pattern: pattern.to_vec(),
                    message,
                },
                span,
            )
        })?;
        let pattern_text = std::str::from_utf8(&translated).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::RegexCompile {
                    id,
                    pattern: pattern.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })?;
        let compiled_pattern = if anchored {
            format!(r"\A(?:{pattern_text})\z")
        } else {
            pattern_text.to_owned()
        };
        RegexBuilder::new(&compiled_pattern)
            .unicode(false)
            .build()
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::RegexCompile {
                        id,
                        pattern: pattern.to_vec(),
                        message: source.to_string(),
                    },
                    span,
                )
            })
    }

    pub(super) fn validate_match_regex_pattern(
        &self,
        id: IrId,
        span: Span,
        pattern: &[u8],
    ) -> Result<(), TreeWalkError> {
        // Bracket expressions are skipped wholesale: inside `[...]` POSIX
        // ERE has no escapes and no metacharacters, so none of the checks
        // below apply there. Their contents are validated during
        // translation (`translate_posix_ere`).
        let mut index = 0;
        while index < pattern.len() {
            match pattern[index] {
                b'\\' => {
                    if let Some(escaped) = pattern.get(index + 1) {
                        if escaped.is_ascii_alphabetic() {
                            return Err(TreeWalkError::new(
                                TreeWalkErrorKind::RegexCompile {
                                    id,
                                    pattern: pattern.to_vec(),
                                    message: "unsupported POSIX ERE escape".to_owned(),
                                },
                                span,
                            ));
                        }
                        index += 2;
                        continue;
                    }
                    // Trailing backslash: reported by the translation step.
                    break;
                }
                b'[' => {
                    match bracket_expression_end(pattern, index) {
                        Some(end) => {
                            index = end + 1;
                            continue;
                        }
                        // Unterminated: reported by the translation step.
                        None => break,
                    }
                }
                b'|' if Self::is_empty_regex_alternative(pattern, index) => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::RegexCompile {
                            id,
                            pattern: pattern.to_vec(),
                            message: "unsupported POSIX ERE empty alternative".to_owned(),
                        },
                        span,
                    ));
                }
                b'?' if self.follows_unescaped_quantifier(pattern, index) => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::RegexCompile {
                            id,
                            pattern: pattern.to_vec(),
                            message: "unsupported POSIX ERE lazy quantifier".to_owned(),
                        },
                        span,
                    ));
                }
                b'(' => {
                    if matches!(pattern.get(index + 1), Some(b'?' | b')')) {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::RegexCompile {
                                id,
                                pattern: pattern.to_vec(),
                                message: "unsupported POSIX ERE group".to_owned(),
                            },
                            span,
                        ));
                    }
                    index += 1;
                }
                _ => index += 1,
            }
        }

        Ok(())
    }

    pub(super) fn is_empty_regex_alternative(pattern: &[u8], index: usize) -> bool {
        let left_empty = index == 0
            || (!Self::regex_byte_is_escaped(pattern, index - 1)
                && matches!(pattern[index - 1], b'(' | b'|'));
        let next = index.saturating_add(1);
        let right_empty = next == pattern.len()
            || (!Self::regex_byte_is_escaped(pattern, next)
                && matches!(pattern[next], b')' | b'|'));
        left_empty || right_empty
    }

    pub(super) fn follows_unescaped_quantifier(&self, pattern: &[u8], index: usize) -> bool {
        let Some(previous_index) = index.checked_sub(1) else {
            return false;
        };
        if Self::regex_byte_is_escaped(pattern, previous_index) {
            return false;
        }
        match pattern[previous_index] {
            b'*' | b'+' | b'?' => true,
            b'}' => Self::interval_quantifier_ends_at(pattern, previous_index),
            _ => false,
        }
    }

    pub(super) fn interval_quantifier_ends_at(pattern: &[u8], end: usize) -> bool {
        if Self::regex_byte_is_escaped(pattern, end) {
            return false;
        }
        let Some(start) = pattern[..end]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, byte)| {
                (*byte == b'{' && !Self::regex_byte_is_escaped(pattern, index)).then_some(index)
            })
        else {
            return false;
        };
        let content = &pattern[start + 1..end];
        if content.is_empty() {
            return false;
        }
        let mut comma_seen = false;
        let mut digit_seen = false;
        for byte in content {
            match *byte {
                b'0'..=b'9' => digit_seen = true,
                b',' if !comma_seen => comma_seen = true,
                _ => return false,
            }
        }
        digit_seen
    }

    pub(super) fn regex_byte_is_escaped(pattern: &[u8], index: usize) -> bool {
        let mut slash_count = 0usize;
        let mut cursor = index;
        while cursor > 0 && pattern[cursor - 1] == b'\\' {
            slash_count = slash_count.saturating_add(1);
            cursor -= 1;
        }
        slash_count % 2 == 1
    }

    pub(super) fn eval_substring_primop(
        &mut self,
        id: IrId,
        span: Span,
        start: IrId,
        len: IrId,
        string_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let start_span = self.node(start)?.span;
        let start_offset = self.eval_int_node(start)? as u32 as i32;
        // C++ Nix truncates to the builtin's signed 32-bit start parameter
        // before reporting the negative-start class.
        if start_offset < 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::NegativeSubstringStart {
                    id: start,
                    start: start_offset.into(),
                },
                start_span,
            ));
        }

        let len = self.eval_int_node(len)? as u32 as usize;
        // Length uses the builtin's unsigned 32-bit parameter, so large and
        // negative Nix integers wrap before substring clamping.

        let string_span = self.node(string_id)?.span;
        let value = self.eval_node(string_id)?;
        let string = self.coerce_to_string(string_id, value, string_span)?;
        let result = {
            let string = self.heap.get_string_view(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_id,
                        source,
                    },
                    string_span,
                )
            })?;
            string
                .try_to_owned()
                .and_then(|string| string.substring_preserve_context(start_offset as usize, len))
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: string_id,
                            source,
                        },
                        string_span,
                    )
                })?
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_replace_strings_primop(
        &mut self,
        id: IrId,
        span: Span,
        from_id: IrId,
        to_id: IrId,
        string_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let from_span = self.node(from_id)?.span;
        let from_value = self.eval_node(from_id)?;
        if from_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: from_id,
                    expected: "list",
                    actual: from_value.tag(),
                },
                from_span,
            ));
        }
        let from_values = {
            let from = self.heap.get_list_view(from_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: from_id,
                        source,
                    },
                    from_span,
                )
            })?;
            let mut values = Vec::new();
            values.try_reserve_exact(from.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: from_id,
                        len: from.len(),
                    },
                    from_span,
                )
            })?;
            values.extend(from.iter());
            values
        };

        let to_span = self.node(to_id)?.span;
        let to_value = self.eval_node(to_id)?;
        if to_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: to_id,
                    expected: "list",
                    actual: to_value.tag(),
                },
                to_span,
            ));
        }
        let to_values = {
            let to = self.heap.get_list_view(to_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id: to_id, source }, to_span)
            })?;
            let mut values = Vec::new();
            values.try_reserve_exact(to.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: to_id,
                        len: to.len(),
                    },
                    to_span,
                )
            })?;
            values.extend(to.iter());
            values
        };

        if from_values.len() != to_values.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ReplaceStringsLengthMismatch {
                    id,
                    from_len: from_values.len(),
                    to_len: to_values.len(),
                },
                span,
            ));
        }

        let mut patterns = Vec::new();
        patterns.try_reserve_exact(from_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: from_values.len(),
                },
                span,
            )
        })?;
        for (from, replacement) in from_values.into_iter().zip(to_values) {
            let from = self.force_value(from_id, from_span, from)?;
            if from.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: from_id,
                        expected: "string",
                        actual: from.tag(),
                    },
                    from_span,
                ));
            }
            let from = {
                let string = self.heap.get_string_view(from).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: from_id,
                            source,
                        },
                        from_span,
                    )
                })?;
                Self::copy_bytes_for_node(from_id, from_span, string.bytes())?
            };
            patterns.push(ReplaceStringPattern { from, replacement });
        }

        let string_span = self.node(string_id)?.span;
        let string_value = self.eval_node(string_id)?;
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
        let (source, context) = {
            let string = self.heap.get_string_view(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_id,
                        source,
                    },
                    string_span,
                )
            })?;
            let source = Self::copy_bytes_for_node(string_id, string_span, string.bytes())?;
            let context = string.context().try_to_owned().map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::String {
                        id: string_id,
                        source,
                    },
                    string_span,
                )
            })?;
            (source, context)
        };

        let result =
            self.replace_strings_bytes(id, span, to_id, to_span, &source, context, &patterns)?;
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn replace_strings_bytes(
        &mut self,
        id: IrId,
        span: Span,
        to_id: IrId,
        to_span: Span,
        source: &[u8],
        mut context: StringContext,
        patterns: &[ReplaceStringPattern],
    ) -> Result<NixString, TreeWalkError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(source.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: source.len(),
                },
                span,
            )
        })?;

        let mut offset = 0;
        while offset <= source.len() {
            let matched = patterns
                .iter()
                .position(|pattern| source[offset..].starts_with(&pattern.from));
            let Some(index) = matched else {
                if offset == source.len() {
                    break;
                }
                Self::extend_bytes_for_node(id, span, &mut bytes, &source[offset..offset + 1])?;
                offset += 1;
                continue;
            };

            let replacement =
                self.force_replace_string(to_id, to_span, patterns[index].replacement)?;
            Self::extend_bytes_for_node(id, span, &mut bytes, &replacement.bytes)?;
            context = context.union(&replacement.context).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?;

            let consumed = patterns[index].from.len();
            if consumed == 0 {
                if offset == source.len() {
                    break;
                }
                Self::extend_bytes_for_node(id, span, &mut bytes, &source[offset..offset + 1])?;
                offset += 1;
            } else {
                offset += consumed;
            }
        }

        Ok(NixString::new(bytes, context))
    }
}
