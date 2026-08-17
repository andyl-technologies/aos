//! Lambda parsing: simple parameters, formal-argument sets, and aliases.

use super::*;

impl<'a> Parser<'a> {
    pub(super) fn parse_simple_lambda(&mut self) -> Result<NodeId, ParseError> {
        let param = self.parse_identifier_node()?;
        self.expect(TokenKind::Colon)?;
        let body = self.parse_expr()?;
        let span = self.join_span(self.node_span(param)?, self.node_span(body)?);
        self.push(
            NodeKind::Lambda,
            span,
            NodeData::Pair {
                first: param,
                second: body,
            },
        )
    }

    pub(super) fn parse_prefixed_formal_lambda(&mut self) -> Result<NodeId, ParseError> {
        let alias_token = self.expect_symbol_token()?;
        let alias = self.intern_token(alias_token)?;
        self.expect(TokenKind::At)?;
        self.parse_formal_lambda(Some(alias))
    }

    pub(super) fn parse_formal_lambda(
        &mut self,
        prefix_alias: Option<Symbol>,
    ) -> Result<NodeId, ParseError> {
        let formal_set = self.parse_formal_set(prefix_alias)?;
        self.expect(TokenKind::Colon)?;
        let body = self.parse_expr()?;
        let span = self.join_span(self.node_span(formal_set)?, self.node_span(body)?);
        self.push(
            NodeKind::Lambda,
            span,
            NodeData::Pair {
                first: formal_set,
                second: body,
            },
        )
    }

    pub(super) fn parse_formal_set(
        &mut self,
        prefix_alias: Option<Symbol>,
    ) -> Result<NodeId, ParseError> {
        let start = self.expect(TokenKind::LBrace)?.span;
        let mut formals = Vec::new();
        let mut formal_names = Vec::new();
        let mut ellipsis = false;

        while self.peek()?.kind != TokenKind::RBrace {
            if self.peek()?.kind == TokenKind::Ellipsis {
                let ellipsis_token = self.peek()?;
                ellipsis = true;
                self.bump()?;
                if self.peek()?.kind != TokenKind::RBrace {
                    return Err(self.error_at(
                        ellipsis_token.span,
                        ParseErrorKind::InvalidFormalPattern {
                            reason: "ellipsis must be the final formal",
                        },
                    ));
                }
                break;
            } else {
                let name_token = self.expect_symbol_token()?;
                let name_span = name_token.span;
                let name = self.intern_token(name_token)?;
                if prefix_alias == Some(name) {
                    return Err(self.error_at(
                        name_span,
                        ParseErrorKind::InvalidFormalPattern {
                            reason: "formal argument duplicates pattern alias",
                        },
                    ));
                }
                if formal_names.contains(&name) {
                    return Err(self.error_at(
                        name_span,
                        ParseErrorKind::InvalidFormalPattern {
                            reason: "duplicate formal argument",
                        },
                    ));
                }
                formal_names.push(name);
                let default = if self.peek()?.kind == TokenKind::Question {
                    self.bump()?;
                    Some(self.parse_expr()?)
                } else {
                    None
                };
                let end = default
                    .map(|node| self.node_span(node))
                    .transpose()?
                    .unwrap_or(name_span);
                formals.push(self.push(
                    NodeKind::Formal,
                    self.join_span(name_span, end),
                    NodeData::Formal { name, default },
                )?);
            }

            if self.peek()?.kind == TokenKind::Comma {
                self.bump()?;
            } else {
                break;
            }
        }

        let end = self.expect(TokenKind::RBrace)?.span;
        let mut alias = prefix_alias;
        if self.peek()?.kind == TokenKind::At {
            if alias.is_some() {
                let at = self.peek()?;
                return Err(self.error_at(
                    at.span,
                    ParseErrorKind::InvalidFormalPattern {
                        reason: "formal set cannot have both prefix and suffix aliases",
                    },
                ));
            }
            self.bump()?;
            let alias_token = self.expect_symbol_token()?;
            let suffix_alias = self.intern_token(alias_token)?;
            if formal_names.contains(&suffix_alias) {
                return Err(self.error_at(
                    alias_token.span,
                    ParseErrorKind::InvalidFormalPattern {
                        reason: "formal argument duplicates pattern alias",
                    },
                ));
            }
            alias = Some(suffix_alias);
        }
        let formals = self.push_child_slice(&formals)?;
        self.push(
            NodeKind::FormalSet,
            self.join_span(start, end),
            NodeData::FormalSet {
                formals,
                ellipsis,
                alias,
            },
        )
    }

    pub(super) fn starts_prefixed_formal_lambda(&mut self) -> Result<bool, ParseError> {
        let mut probe = self.probe();
        if probe.bump()?.kind != TokenKind::Ident {
            return Ok(false);
        }
        Ok(probe.bump()?.kind == TokenKind::At && probe.bump()?.kind == TokenKind::LBrace)
    }

    pub(super) fn starts_formal_lambda(&mut self) -> Result<bool, ParseError> {
        let mut probe = self.probe();
        if !probe.consume_formal_set_shape()? {
            return Ok(false);
        }

        if probe.peek()?.kind == TokenKind::At {
            probe.bump()?;
            if probe.bump()?.kind != TokenKind::Ident {
                return Ok(false);
            }
        }

        Ok(probe.peek()?.kind == TokenKind::Colon)
    }
}
