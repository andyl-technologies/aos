//! Keyword-led expression forms and the Pratt operator-precedence loop.

use super::*;

impl<'a> Parser<'a> {
    pub(super) fn parse_let_in(&mut self) -> Result<NodeId, ParseError> {
        let start = self.expect(TokenKind::Let)?.span;
        if self.peek()?.kind == TokenKind::LBrace {
            return self.parse_legacy_let_attrset(start);
        }
        let bindings = self.parse_bindings_until(TokenKind::In)?;
        self.expect(TokenKind::In)?;
        let body = self.parse_expr()?;
        let span = self.join_span(start, self.node_span(body)?);
        self.push(NodeKind::LetIn, span, NodeData::LetIn { bindings, body })
    }

    fn parse_legacy_let_attrset(&mut self, start: Span) -> Result<NodeId, ParseError> {
        self.expect(TokenKind::LBrace)?;
        let bindings = self.parse_bindings_until(TokenKind::RBrace)?;
        let end = self.expect(TokenKind::RBrace)?.span;
        let body_span = self.legacy_let_body_span(bindings)?.unwrap_or(start);
        let body_symbol = self.intern_bytes(b"body")?;
        let body_segment = self.push(NodeKind::Ident, body_span, NodeData::Symbol(body_symbol))?;
        let body_path = self.push_child_slice(&[body_segment])?;
        let receiver = self.push(
            NodeKind::RecAttrSet,
            self.join_span(start, end),
            NodeData::Children(bindings),
        )?;
        self.push(
            NodeKind::Select,
            self.join_span(start, end),
            NodeData::Select {
                receiver,
                path: body_path,
                default: None,
            },
        )
    }

    fn legacy_let_body_span(&self, bindings: ChildSlice) -> Result<Option<Span>, ParseError> {
        for binding in self.child_ids(bindings)? {
            let node = self.node(binding)?;
            let NodeData::Binding { path, .. } = node.data else {
                continue;
            };
            let Some(segment) = self.child_ids(path)?.first().copied() else {
                continue;
            };
            let Some(symbol) = self.static_attr_symbol(segment)? else {
                continue;
            };
            if self.symbols.resolve(symbol) == Some(b"body".as_slice()) {
                return Ok(Some(self.node_span(segment)?));
            }
        }
        Ok(None)
    }

    pub(super) fn parse_with(&mut self) -> Result<NodeId, ParseError> {
        let start = self.expect(TokenKind::With)?.span;
        let scrutinee = self.parse_expr()?;
        self.expect(TokenKind::Semi)?;
        let body = self.parse_expr()?;
        let span = self.join_span(start, self.node_span(body)?);
        self.push(
            NodeKind::With,
            span,
            NodeData::Pair {
                first: scrutinee,
                second: body,
            },
        )
    }

    pub(super) fn parse_assert(&mut self) -> Result<NodeId, ParseError> {
        let start = self.expect(TokenKind::Assert)?.span;
        let condition = self.parse_expr()?;
        self.expect(TokenKind::Semi)?;
        let body = self.parse_expr()?;
        let span = self.join_span(start, self.node_span(body)?);
        self.push(
            NodeKind::Assert,
            span,
            NodeData::Pair {
                first: condition,
                second: body,
            },
        )
    }

    pub(super) fn parse_if(&mut self) -> Result<NodeId, ParseError> {
        let start = self.expect(TokenKind::If)?.span;
        let condition = self.parse_expr()?;
        self.expect(TokenKind::Then)?;
        let then_branch = self.parse_expr()?;
        self.expect(TokenKind::Else)?;
        let else_branch = self.parse_expr()?;
        let span = self.join_span(start, self.node_span(else_branch)?);
        self.push(
            NodeKind::IfThenElse,
            span,
            NodeData::Triple {
                first: condition,
                second: then_branch,
                third: else_branch,
            },
        )
    }

    pub(super) fn parse_pratt(&mut self, min_bp: u8) -> Result<NodeId, ParseError> {
        let mut lhs = self.parse_prefix()?;
        let mut non_assoc_bp = None;

        loop {
            let next = self.peek()?;

            if next.kind == TokenKind::Dot {
                if BP_SELECT < min_bp {
                    break;
                }
                self.bump()?;
                let path = self.parse_attr_path()?;
                let default = if self.peek()?.kind == TokenKind::Or {
                    self.bump()?;
                    Some(self.parse_select_expr()?)
                } else {
                    None
                };
                let end = default
                    .map(|node| self.node_span(node))
                    .transpose()?
                    .unwrap_or_else(|| self.slice_span(path));
                lhs = self.push(
                    NodeKind::Select,
                    self.join_span(self.node_span(lhs)?, end),
                    NodeData::Select {
                        receiver: lhs,
                        path,
                        default,
                    },
                )?;
                continue;
            }

            if next.kind == TokenKind::Question {
                if BP_HAS_ATTR < min_bp {
                    break;
                }
                if non_assoc_bp == Some(BP_HAS_ATTR) {
                    return Err(self.error_at(
                        next.span,
                        ParseErrorKind::NonAssociativeOperator { operator: "?" },
                    ));
                }
                self.bump()?;
                let path = self.parse_attr_path()?;
                lhs = self.push(
                    NodeKind::HasAttr,
                    self.join_span(self.node_span(lhs)?, self.slice_span(path)),
                    NodeData::HasAttr {
                        receiver: lhs,
                        path,
                    },
                )?;
                non_assoc_bp = Some(BP_HAS_ATTR);
                continue;
            }

            if self.starts_application_arg(next.kind) && BP_APPLY >= min_bp {
                let rhs = if next.kind == TokenKind::Or {
                    let rhs = self.parse_attr_symbol_node()?;
                    let tail = self.peek()?;
                    if matches!(tail.kind, TokenKind::Dot | TokenKind::Or) {
                        return Err(self.error_at(
                            tail.span,
                            ParseErrorKind::UnexpectedToken {
                                expected: "operator or end of expression",
                                found: tail.kind,
                            },
                        ));
                    }
                    rhs
                } else {
                    self.parse_pratt(BP_APPLY + 1)?
                };
                lhs = self.push(
                    NodeKind::Apply,
                    self.join_span(self.node_span(lhs)?, self.node_span(rhs)?),
                    NodeData::Pair {
                        first: lhs,
                        second: rhs,
                    },
                )?;
                continue;
            }

            let Some(op) = infix_operator(next.kind) else {
                break;
            };
            if op.left_bp < min_bp {
                break;
            }
            if op.assoc == Assoc::None && non_assoc_bp == Some(op.left_bp) {
                return Err(self.error_at(
                    next.span,
                    ParseErrorKind::NonAssociativeOperator { operator: op.name },
                ));
            }

            self.bump()?;
            let rhs = self.parse_pratt(op.right_bp)?;
            lhs = self.push(
                NodeKind::BinOp,
                self.join_span(self.node_span(lhs)?, self.node_span(rhs)?),
                NodeData::Binary {
                    op: op.kind,
                    lhs,
                    rhs,
                },
            )?;

            if op.assoc == Assoc::None {
                non_assoc_bp = Some(op.left_bp);
            }
        }

        Ok(lhs)
    }

    pub(super) fn parse_prefix(&mut self) -> Result<NodeId, ParseError> {
        let token = self.peek()?;
        match token.kind {
            TokenKind::Minus => {
                let start = self.bump()?.span;
                let operand = self.parse_pratt(BP_NEG_PREFIX)?;
                self.push(
                    NodeKind::UnaryOp,
                    self.join_span(start, self.node_span(operand)?),
                    NodeData::Unary {
                        op: UnaryOpKind::Neg,
                        operand,
                    },
                )
            }
            TokenKind::Not => {
                let start = self.bump()?.span;
                let operand = self.parse_pratt(BP_NOT_PREFIX)?;
                self.push(
                    NodeKind::UnaryOp,
                    self.join_span(start, self.node_span(operand)?),
                    NodeData::Unary {
                        op: UnaryOpKind::Not,
                        operand,
                    },
                )
            }
            _ => self.parse_primary(),
        }
    }

    pub(super) fn parse_primary(&mut self) -> Result<NodeId, ParseError> {
        let token = self.peek()?;
        match token.kind {
            TokenKind::Int => self.parse_int(),
            TokenKind::Float => self.parse_float(),
            TokenKind::Ident => self.parse_identifier_node(),
            TokenKind::Path => self.parse_path(),
            TokenKind::SPath => self.parse_symbol_node(NodeKind::SearchPath),
            TokenKind::Uri => self.parse_symbol_node(NodeKind::Uri),
            TokenKind::StrStart => {
                self.parse_string(TokenKind::StrEnd, NodeKind::Str, StringSyntax::Double)
            }
            TokenKind::IndStrStart => {
                self.parse_string(TokenKind::IndStrEnd, NodeKind::Str, StringSyntax::Indented)
            }
            TokenKind::LParen => self.parse_paren(),
            TokenKind::LBracket => self.parse_list(),
            TokenKind::LBrace => self.parse_attrset(false),
            TokenKind::Rec => self.parse_rec_attrset(),
            _ => Err(self.error_at(
                token.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "expression",
                    found: token.kind,
                },
            )),
        }
    }

    pub(super) fn parse_select_expr(&mut self) -> Result<NodeId, ParseError> {
        let mut lhs = self.parse_primary()?;
        while self.peek()?.kind == TokenKind::Dot {
            self.bump()?;
            let path = self.parse_attr_path()?;
            let default = if self.peek()?.kind == TokenKind::Or {
                self.bump()?;
                Some(self.parse_select_expr()?)
            } else {
                None
            };
            let end = default
                .map(|node| self.node_span(node))
                .transpose()?
                .unwrap_or_else(|| self.slice_span(path));
            lhs = self.push(
                NodeKind::Select,
                self.join_span(self.node_span(lhs)?, end),
                NodeData::Select {
                    receiver: lhs,
                    path,
                    default,
                },
            )?;
        }
        Ok(lhs)
    }
}
