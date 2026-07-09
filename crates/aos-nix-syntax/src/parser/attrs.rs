//! Attribute sets, `let`/`inherit` bindings, attribute paths, and the
//! parse-time binding normalization and merging logic.

use super::*;

impl<'a> Parser<'a> {
    pub(super) fn parse_rec_attrset(&mut self) -> Result<NodeId, ParseError> {
        self.expect(TokenKind::Rec)?;
        self.parse_attrset(true)
    }

    pub(super) fn parse_attrset(&mut self, recursive: bool) -> Result<NodeId, ParseError> {
        let start = self.expect(TokenKind::LBrace)?.span;
        let bindings = self.parse_bindings_until(TokenKind::RBrace)?;
        let end = self.expect(TokenKind::RBrace)?.span;
        self.push(
            if recursive {
                NodeKind::RecAttrSet
            } else {
                NodeKind::AttrSet
            },
            self.join_span(start, end),
            NodeData::Children(bindings),
        )
    }

    pub(super) fn parse_bindings_until(
        &mut self,
        terminator: TokenKind,
    ) -> Result<ChildSlice, ParseError> {
        let mut bindings = Vec::new();
        while self.peek()?.kind != terminator {
            if self.peek()?.kind == TokenKind::Eof {
                let eof = self.peek()?;
                return Err(self.error_at(
                    eof.span,
                    ParseErrorKind::UnexpectedToken {
                        expected: "binding terminator",
                        found: eof.kind,
                    },
                ));
            }
            bindings.extend(self.parse_binding()?);
        }
        let bindings = self.normalize_bindings(bindings)?;
        self.push_child_slice(&bindings)
    }

    pub(super) fn parse_binding(&mut self) -> Result<Vec<NodeId>, ParseError> {
        if self.peek()?.kind == TokenKind::Inherit {
            return self.parse_inherit();
        }

        let path = self.parse_attr_path()?;
        self.expect(TokenKind::Assign)?;
        let value = self.parse_expr()?;
        let semi = self.expect(TokenKind::Semi)?.span;
        let binding = self.push(
            NodeKind::Binding,
            self.join_span(self.slice_span(path), semi),
            NodeData::Binding { path, value },
        )?;
        Ok(vec![binding])
    }

    pub(super) fn parse_inherit(&mut self) -> Result<Vec<NodeId>, ParseError> {
        let start = self.expect(TokenKind::Inherit)?.span;
        let from = if self.peek()?.kind == TokenKind::LParen {
            self.bump()?;
            let expr = self.parse_expr()?;
            self.expect(TokenKind::RParen)?;
            Some(expr)
        } else {
            None
        };

        let mut names = Vec::new();
        while self.peek()?.kind != TokenKind::Semi {
            names.push(self.parse_attr_segment()?);
        }
        let end = self.expect(TokenKind::Semi)?.span;
        if names.is_empty() {
            let Some(from) = from else {
                return Ok(Vec::new());
            };
            let names = self.push_child_slice(&[])?;
            let inherit = self.push(
                NodeKind::Inherit,
                self.join_span(start, end),
                NodeData::Inherit {
                    from: Some(from),
                    names,
                },
            )?;
            return Ok(vec![inherit]);
        }
        let mut bindings = Vec::with_capacity(names.len());
        for name in names {
            let path = self.push_child_slice(&[name])?;
            let names = self.push_child_slice(&[name])?;
            let inherit = self.push(
                NodeKind::Inherit,
                self.join_span(start, end),
                NodeData::Inherit { from, names },
            )?;
            bindings.push(self.push(
                NodeKind::Binding,
                self.join_span(start, end),
                NodeData::Binding {
                    path,
                    value: inherit,
                },
            )?);
        }
        Ok(bindings)
    }

    pub(super) fn parse_attr_path(&mut self) -> Result<ChildSlice, ParseError> {
        let mut segments = vec![self.parse_attr_segment()?];
        while self.peek()?.kind == TokenKind::Dot {
            self.bump()?;
            segments.push(self.parse_attr_segment()?);
        }
        self.push_child_slice(&segments)
    }

    pub(super) fn normalize_bindings(
        &mut self,
        bindings: Vec<NodeId>,
    ) -> Result<Vec<NodeId>, ParseError> {
        let mut merged = Vec::new();
        for binding in bindings {
            let binding = self.normalize_binding_path(binding)?;
            let Some(symbol) = self.binding_target_symbol(binding)? else {
                merged.push(binding);
                continue;
            };

            let mut merged_binding = Some(binding);
            for existing in &mut merged {
                if self.binding_target_symbol(*existing)? == Some(symbol) {
                    *existing = self.merge_binding_nodes(*existing, binding)?;
                    merged_binding = None;
                    break;
                }
            }
            if let Some(binding) = merged_binding {
                merged.push(binding);
            }
        }
        Ok(merged)
    }

    pub(super) fn normalize_binding_path(&mut self, binding: NodeId) -> Result<NodeId, ParseError> {
        let node = self.node(binding)?;
        if node.kind != NodeKind::Binding {
            return Ok(binding);
        }
        let NodeData::Binding { path, value } = node.data else {
            return Ok(binding);
        };
        let segments = self.child_ids(path)?;
        if segments.len() <= 1 {
            return Ok(binding);
        }
        self.nested_binding(&segments, value, Some(node.span))
    }

    pub(super) fn nested_binding(
        &mut self,
        segments: &[NodeId],
        value: NodeId,
        span_override: Option<Span>,
    ) -> Result<NodeId, ParseError> {
        let Some((&head, tail)) = segments.split_first() else {
            return Err(self.error_at(self.node_span(value)?, ParseErrorKind::InvalidBindingPath));
        };
        let path = self.push_child_slice(&[head])?;
        let value = if tail.is_empty() {
            value
        } else {
            let nested = self.nested_binding(tail, value, span_override)?;
            let children = self.push_child_slice(&[nested])?;
            let span = self.join_span(self.node_span(tail[0])?, self.node_span(value)?);
            self.push(NodeKind::AttrSet, span, NodeData::Children(children))?
        };
        let span = if let Some(span) = span_override {
            span
        } else {
            self.join_span(self.node_span(head)?, self.node_span(value)?)
        };
        self.push(NodeKind::Binding, span, NodeData::Binding { path, value })
    }

    pub(super) fn merge_binding_nodes(
        &mut self,
        existing: NodeId,
        incoming: NodeId,
    ) -> Result<NodeId, ParseError> {
        let existing_node = self.node(existing)?;
        let incoming_node = self.node(incoming)?;
        let NodeData::Binding {
            path,
            value: existing_value,
        } = existing_node.data
        else {
            return Ok(incoming);
        };
        let NodeData::Binding {
            value: incoming_value,
            ..
        } = incoming_node.data
        else {
            return Ok(incoming);
        };

        let value = self.merge_binding_values(
            existing_value,
            incoming_value,
            existing_node.span,
            incoming_node.span,
        )?;
        self.push(
            NodeKind::Binding,
            self.join_span(existing_node.span, incoming_node.span),
            NodeData::Binding { path, value },
        )
    }

    pub(super) fn merge_binding_values(
        &mut self,
        existing: NodeId,
        incoming: NodeId,
        existing_binding_span: Span,
        incoming_binding_span: Span,
    ) -> Result<NodeId, ParseError> {
        let existing_node = self.node(existing)?;
        let incoming_node = self.node(incoming)?;
        if !Self::is_attrset_kind(existing_node.kind) || !Self::is_attrset_kind(incoming_node.kind)
        {
            return Err(self.error_at(
                incoming_binding_span,
                ParseErrorKind::DuplicateAttribute {
                    first: existing_binding_span,
                    second: incoming_binding_span,
                },
            ));
        }

        let NodeData::Children(existing_bindings) = existing_node.data else {
            return Err(self.error_at(existing_node.span, ParseErrorKind::InvalidBindingPath));
        };
        let NodeData::Children(incoming_bindings) = incoming_node.data else {
            return Err(self.error_at(incoming_node.span, ParseErrorKind::InvalidBindingPath));
        };

        let mut bindings = self.child_ids(existing_bindings)?;
        bindings.extend(self.child_ids(incoming_bindings)?);
        let bindings = self.normalize_bindings(bindings)?;
        let bindings = self.push_child_slice(&bindings)?;
        // Nix preserves the first attrset's recursive/plain scope when later
        // bindings merge into the same prefix.
        self.push(
            existing_node.kind,
            self.join_span(existing_node.span, incoming_node.span),
            NodeData::Children(bindings),
        )
    }

    pub(super) fn binding_target_symbol(
        &self,
        binding: NodeId,
    ) -> Result<Option<Symbol>, ParseError> {
        let node = self.node(binding)?;
        let NodeData::Binding { path, .. } = node.data else {
            return Ok(None);
        };
        let Some(segment) = self.child_ids(path)?.first().copied() else {
            return Ok(None);
        };
        self.static_attr_symbol(segment)
    }

    pub(super) fn static_attr_symbol(&self, node: NodeId) -> Result<Option<Symbol>, ParseError> {
        let node = self.node(node)?;
        match node.kind {
            NodeKind::Ident | NodeKind::Str => self.symbol_payload(node).map(Some),
            NodeKind::Interp => {
                let NodeData::Node(child) = node.data else {
                    return Ok(None);
                };
                let child = self.node(child)?;
                if child.kind == NodeKind::Str {
                    self.symbol_payload(child).map(Some)
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    pub(super) fn symbol_payload(&self, node: Node) -> Result<Symbol, ParseError> {
        let NodeData::Symbol(symbol) = node.data else {
            return Err(self.error_at(node.span, ParseErrorKind::InvalidBindingPath));
        };
        Ok(symbol)
    }

    pub(super) fn is_attrset_kind(kind: NodeKind) -> bool {
        matches!(kind, NodeKind::AttrSet | NodeKind::RecAttrSet)
    }

    pub(super) fn parse_attr_segment(&mut self) -> Result<NodeId, ParseError> {
        let token = self.peek()?;
        match token.kind {
            TokenKind::Ident | TokenKind::Or => self.parse_attr_symbol_node(),
            TokenKind::StrStart => {
                let node =
                    self.parse_string(TokenKind::StrEnd, NodeKind::Str, StringSyntax::Double)?;
                self.wrap_quoted_interp_attr_segment(node)
            }
            TokenKind::IndStrStart => {
                let node =
                    self.parse_string(TokenKind::IndStrEnd, NodeKind::Str, StringSyntax::Indented)?;
                self.wrap_quoted_interp_attr_segment(node)
            }
            TokenKind::DollarBrace => {
                let start = self.bump()?.span;
                let expr = self.parse_expr()?;
                let end = self.expect(TokenKind::RBrace)?.span;
                self.push(
                    NodeKind::Interp,
                    self.join_span(start, end),
                    NodeData::Node(expr),
                )
            }
            _ => Err(self.error_at(
                token.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "attribute path segment",
                    found: token.kind,
                },
            )),
        }
    }

    /// Re-wraps a quoted attribute key that collapsed to a bare interpolation.
    ///
    /// [`Parser::parse_string`] collapses a single-interpolation string such
    /// as `"${e}"` to the inner `Interp` node, which makes it structurally
    /// identical to a plain dynamic key `${e}`. The two forms diverge in Nix:
    /// a plain `${e}` binding whose name evaluates to `null` is skipped (and
    /// the bare expression is a static key when it is a string literal),
    /// while the quoted form is a string interpolation that always coerces —
    /// erroring on `null` — and is always a dynamic key. Wrapping the
    /// collapsed node in a second `Interp` layer preserves the string
    /// coercion, matching the shape a plain `${"${e}"}` key already lowers
    /// to. Literal strings and multi-fragment interpolations keep their
    /// shape: both already carry the correct semantics.
    fn wrap_quoted_interp_attr_segment(&mut self, node_id: NodeId) -> Result<NodeId, ParseError> {
        let node = self.node(node_id)?;
        if node.kind == NodeKind::Interp && matches!(node.data, NodeData::Node(_)) {
            return self.push(NodeKind::Interp, node.span, NodeData::Node(node_id));
        }
        Ok(node_id)
    }
}
