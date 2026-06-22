//! String literal parsing: double-quoted and indented strings, escape
//! decoding, interpolation fragments, and indentation stripping.

use super::*;

impl<'a> Parser<'a> {
    pub(super) fn parse_string(
        &mut self,
        end_kind: TokenKind,
        literal_kind: NodeKind,
        syntax: StringSyntax,
    ) -> Result<NodeId, ParseError> {
        let start = self.bump()?.span;
        let mut fragments = Vec::new();

        loop {
            let token = self.peek()?;
            match token.kind {
                TokenKind::StrPart => {
                    let token = self.bump()?;
                    fragments.push(StringFragment::Literal {
                        span: token.span,
                        bytes: decode_double_string_fragment(self.token_bytes(token)?),
                        has_indentation: true,
                    });
                }
                TokenKind::IndStrPart => {
                    let token = self.bump()?;
                    fragments.extend(decode_indented_string_fragment(
                        token.span,
                        self.token_bytes(token)?,
                    ));
                }
                TokenKind::DollarBrace => {
                    let interp_start = self.bump()?.span;
                    let expr = self.parse_expr()?;
                    let interp_end = self.expect(TokenKind::RBrace)?.span;
                    let node = self.push(
                        NodeKind::Interp,
                        self.join_span(interp_start, interp_end),
                        NodeData::Node(expr),
                    )?;
                    fragments.push(StringFragment::Interpolation(node));
                }
                kind if kind == end_kind => {
                    let end = self.bump()?.span;
                    if syntax == StringSyntax::Indented {
                        fragments = strip_indented_string_fragments(fragments);
                    }
                    return self.materialize_string_fragments(start, end, literal_kind, fragments);
                }
                _ => {
                    return Err(self.error_at(
                        token.span,
                        ParseErrorKind::UnexpectedToken {
                            expected: "string fragment or string end",
                            found: token.kind,
                        },
                    ));
                }
            }
        }
    }

    pub(super) fn materialize_string_fragments(
        &mut self,
        start: Span,
        end: Span,
        literal_kind: NodeKind,
        fragments: Vec<StringFragment>,
    ) -> Result<NodeId, ParseError> {
        let mut nodes = Vec::new();
        let mut pending_literal = Vec::new();
        let mut pending_span = None;
        for fragment in fragments {
            match fragment {
                StringFragment::Literal { span, bytes, .. } => {
                    if bytes.is_empty() {
                        continue;
                    }
                    pending_span = Some(
                        pending_span
                            .map(|existing| self.join_span(existing, span))
                            .unwrap_or(span),
                    );
                    pending_literal.extend_from_slice(&bytes);
                }
                StringFragment::Interpolation(node) => {
                    self.flush_string_literal(
                        literal_kind,
                        &mut nodes,
                        &mut pending_literal,
                        &mut pending_span,
                    )?;
                    nodes.push(node);
                }
            }
        }
        self.flush_string_literal(
            literal_kind,
            &mut nodes,
            &mut pending_literal,
            &mut pending_span,
        )?;

        let full_span = self.join_span(start, end);
        if nodes.is_empty() {
            let symbol = self.intern_bytes(&[])?;
            return self.push(literal_kind, full_span, NodeData::Symbol(symbol));
        }

        if nodes.len() == 1 {
            if let Some(node) = self.arena.node_mut(nodes[0]) {
                node.span = full_span;
            }
            return Ok(nodes[0]);
        }

        let children = self.push_child_slice(&nodes)?;
        self.push(NodeKind::Interp, full_span, NodeData::Children(children))
    }

    pub(super) fn flush_string_literal(
        &mut self,
        literal_kind: NodeKind,
        nodes: &mut Vec<NodeId>,
        pending_literal: &mut Vec<u8>,
        pending_span: &mut Option<Span>,
    ) -> Result<(), ParseError> {
        if pending_literal.is_empty() {
            *pending_span = None;
            return Ok(());
        }
        let span = pending_span.take().unwrap_or_default();
        let symbol = self.intern_bytes(pending_literal)?;
        nodes.push(self.push(literal_kind, span, NodeData::Symbol(symbol))?);
        pending_literal.clear();
        Ok(())
    }
}

fn decode_double_string_fragment(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        cursor += 1;
        if byte == b'\\' {
            if let Some(escaped) = bytes.get(cursor).copied() {
                cursor += 1;
                out.push(unescaped_byte(escaped));
            } else {
                out.push(byte);
            }
        } else if byte == b'\r' {
            out.push(b'\n');
            if bytes.get(cursor) == Some(&b'\n') {
                cursor += 1;
            }
        } else {
            out.push(byte);
        }
    }
    out
}

fn decode_indented_string_fragment(span: Span, bytes: &[u8]) -> Vec<StringFragment> {
    let mut fragments = Vec::new();
    let mut plain = Vec::new();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"''$") {
            push_plain_indented(&mut fragments, span, &mut plain);
            fragments.push(StringFragment::Literal {
                span,
                bytes: vec![b'$'],
                has_indentation: false,
            });
            cursor += 3;
        } else if bytes[cursor..].starts_with(b"'''") {
            push_plain_indented(&mut fragments, span, &mut plain);
            fragments.push(StringFragment::Literal {
                span,
                bytes: b"''".to_vec(),
                has_indentation: false,
            });
            cursor += 3;
        } else if bytes[cursor..].starts_with(b"''\\") && cursor + 3 < bytes.len() {
            push_plain_indented(&mut fragments, span, &mut plain);
            fragments.push(StringFragment::Literal {
                span,
                bytes: vec![unescaped_byte(bytes[cursor + 3])],
                has_indentation: false,
            });
            cursor += 4;
        } else {
            plain.push(bytes[cursor]);
            cursor += 1;
        }
    }

    push_plain_indented(&mut fragments, span, &mut plain);
    fragments
}

fn push_plain_indented(fragments: &mut Vec<StringFragment>, span: Span, plain: &mut Vec<u8>) {
    if plain.is_empty() {
        return;
    }
    fragments.push(StringFragment::Literal {
        span,
        bytes: std::mem::take(plain),
        has_indentation: true,
    });
}

fn unescaped_byte(byte: u8) -> u8 {
    match byte {
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        byte => byte,
    }
}

fn strip_indented_string_fragments(mut fragments: Vec<StringFragment>) -> Vec<StringFragment> {
    elide_opening_indented_newline(&mut fragments);
    let min_indent = common_indentation(&fragments);
    trim_indented_fragments(fragments, min_indent)
}

fn elide_opening_indented_newline(fragments: &mut [StringFragment]) {
    let Some(StringFragment::Literal { bytes, .. }) = fragments.first_mut() else {
        return;
    };
    let mut cursor = 0usize;
    while bytes.get(cursor) == Some(&b' ') {
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b'\n') {
        bytes.drain(..=cursor);
    }
}

fn common_indentation(fragments: &[StringFragment]) -> usize {
    let mut at_start_of_line = true;
    let mut min_indent = INDENT_INFINITY;
    let mut cur_indent = 0usize;

    for fragment in fragments {
        match fragment {
            StringFragment::Interpolation(_) => {
                if at_start_of_line {
                    at_start_of_line = false;
                    min_indent = min_indent.min(cur_indent);
                }
            }
            StringFragment::Literal {
                bytes,
                has_indentation,
                ..
            } => {
                if !has_indentation {
                    if at_start_of_line {
                        at_start_of_line = false;
                        min_indent = min_indent.min(cur_indent);
                    }
                    continue;
                }

                for byte in bytes {
                    if at_start_of_line {
                        match *byte {
                            b' ' => cur_indent += 1,
                            b'\n' => cur_indent = 0,
                            _ => {
                                at_start_of_line = false;
                                min_indent = min_indent.min(cur_indent);
                            }
                        }
                    } else if *byte == b'\n' {
                        at_start_of_line = true;
                        cur_indent = 0;
                    }
                }
            }
        }
    }

    min_indent
}

fn trim_indented_fragments(
    fragments: Vec<StringFragment>,
    min_indent: usize,
) -> Vec<StringFragment> {
    let mut trimmed = Vec::new();
    let mut at_start_of_line = true;
    let mut cur_dropped = 0usize;
    let total = fragments.len();

    for (index, fragment) in fragments.into_iter().enumerate() {
        let remaining = total - index;
        match fragment {
            StringFragment::Interpolation(node) => {
                at_start_of_line = false;
                cur_dropped = 0;
                trimmed.push(StringFragment::Interpolation(node));
            }
            StringFragment::Literal { span, bytes, .. } => {
                let mut out = Vec::with_capacity(bytes.len());
                for byte in bytes {
                    if at_start_of_line {
                        match byte {
                            b' ' => {
                                if cur_dropped >= min_indent {
                                    out.push(byte);
                                }
                                cur_dropped += 1;
                            }
                            b'\n' => {
                                cur_dropped = 0;
                                out.push(byte);
                            }
                            _ => {
                                at_start_of_line = false;
                                cur_dropped = 0;
                                out.push(byte);
                            }
                        }
                    } else {
                        out.push(byte);
                        if byte == b'\n' {
                            at_start_of_line = true;
                        }
                    }
                }

                if remaining == 1 {
                    trim_final_space_only_line(&mut out);
                }
                if !out.is_empty() {
                    trimmed.push(StringFragment::Literal {
                        span,
                        bytes: out,
                        has_indentation: true,
                    });
                }
            }
        }
    }

    trimmed
}

fn trim_final_space_only_line(bytes: &mut Vec<u8>) {
    let Some(newline) = bytes.iter().rposition(|byte| *byte == b'\n') else {
        return;
    };
    if bytes[newline + 1..].iter().all(|byte| *byte == b' ') {
        bytes.truncate(newline + 1);
    }
}
