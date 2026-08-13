//! Atomic primaries: numeric and symbol literals, paths, parens, and lists.

use super::*;

impl<'a> Parser<'a> {
    pub(super) fn parse_int(&mut self) -> Result<NodeId, ParseError> {
        let token = self.expect(TokenKind::Int)?;
        let text = self.token_text(token)?;
        let value = text.parse::<i64>().map_err(|_| {
            self.error_at(
                token.span,
                ParseErrorKind::InvalidLiteral { kind: "integer" },
            )
        })?;
        self.push(NodeKind::Int, token.span, NodeData::Int(value))
    }

    pub(super) fn parse_float(&mut self) -> Result<NodeId, ParseError> {
        let token = self.expect(TokenKind::Float)?;
        let text = self.token_text(token)?;
        let value = text.parse::<f64>().map_err(|_| {
            self.error_at(token.span, ParseErrorKind::InvalidLiteral { kind: "float" })
        })?;
        self.push(NodeKind::Float, token.span, NodeData::Float(value))
    }

    pub(super) fn parse_identifier_node(&mut self) -> Result<NodeId, ParseError> {
        let token = self.expect(TokenKind::Ident)?;
        let symbol = self.intern_token(token)?;
        self.push(NodeKind::Ident, token.span, NodeData::Symbol(symbol))
    }

    pub(super) fn parse_symbol_node(&mut self, kind: NodeKind) -> Result<NodeId, ParseError> {
        let token = self.expect_symbol_like()?;
        let symbol = self.intern_token(token)?;
        self.push(kind, token.span, NodeData::Symbol(symbol))
    }

    pub(super) fn parse_attr_symbol_node(&mut self) -> Result<NodeId, ParseError> {
        let token = self.bump()?;
        if matches!(token.kind, TokenKind::Ident | TokenKind::Or) {
            let symbol = self.intern_token(token)?;
            self.push(NodeKind::Ident, token.span, NodeData::Symbol(symbol))
        } else {
            Err(self.error_at(
                token.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "attribute path segment",
                    found: token.kind,
                },
            ))
        }
    }

    pub(super) fn parse_path(&mut self) -> Result<NodeId, ParseError> {
        let first = self.expect(TokenKind::Path)?;
        let mut trailing_slash = self.path_token_has_trailing_slash(first)?;
        let mut trailing_slash_span = first.span;
        let first_symbol = self.intern_token(first)?;
        let first_node = self.push(NodeKind::Path, first.span, NodeData::Symbol(first_symbol))?;
        let mut fragments = vec![first_node];
        let mut end = first.span;

        loop {
            let next = self.peek()?;
            if next.span.start != end.end {
                break;
            }

            match next.kind {
                TokenKind::DollarBrace => {
                    let start = self.bump()?.span;
                    let expr = self.parse_expr()?;
                    let close = self.expect(TokenKind::RBrace)?.span;
                    end = close;
                    trailing_slash = false;
                    fragments.push(self.push(
                        NodeKind::Interp,
                        self.join_span(start, close),
                        NodeData::Node(expr),
                    )?);
                }
                TokenKind::Path => {
                    let token = self.bump()?;
                    trailing_slash = self.path_token_has_trailing_slash(token)?;
                    trailing_slash_span = token.span;
                    let symbol = self.intern_token(token)?;
                    end = token.span;
                    fragments.push(self.push(
                        NodeKind::Path,
                        token.span,
                        NodeData::Symbol(symbol),
                    )?);
                }
                _ => break,
            }
        }

        if trailing_slash {
            return Err(self.error_at(trailing_slash_span, ParseErrorKind::PathTrailingSlash));
        }

        if fragments.len() == 1 {
            Ok(first_node)
        } else {
            let children = self.push_child_slice(&fragments)?;
            self.push(
                NodeKind::Interp,
                self.join_span(first.span, end),
                NodeData::Children(children),
            )
        }
    }

    pub(super) fn path_token_has_trailing_slash(&self, token: Token) -> Result<bool, ParseError> {
        Ok(self.token_bytes(token)?.ends_with(b"/"))
    }

    pub(super) fn parse_paren(&mut self) -> Result<NodeId, ParseError> {
        self.expect(TokenKind::LParen)?;
        let expr = self.parse_expr()?;
        self.expect(TokenKind::RParen)?;
        Ok(expr)
    }

    pub(super) fn parse_list(&mut self) -> Result<NodeId, ParseError> {
        let start = self.expect(TokenKind::LBracket)?.span;
        let mut elements = Vec::new();
        while self.peek()?.kind != TokenKind::RBracket {
            if self.peek()?.kind == TokenKind::Eof {
                let eof = self.peek()?;
                return Err(self.error_at(
                    eof.span,
                    ParseErrorKind::UnexpectedToken {
                        expected: "]",
                        found: eof.kind,
                    },
                ));
            }
            elements.push(self.parse_select_expr()?);
        }
        let end = self.expect(TokenKind::RBracket)?.span;
        let children = self.push_child_slice(&elements)?;
        self.push(
            NodeKind::List,
            self.join_span(start, end),
            NodeData::Children(children),
        )
    }
}
