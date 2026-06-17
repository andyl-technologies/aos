//! Recursive-descent and Pratt parser for Nix source.
//!
//! The parser consumes [`Token`]s from the hand-written lexer, skips retained
//! trivia, and writes directly into the compact [`AstArena`]. Keyword-led forms
//! use recursive descent, while application and operators are parsed with a
//! Pratt loop whose binding powers encode Nix precedence and associativity.

use std::str;

use thiserror::Error;

use super::{
    AstArena, AstError, AstErrorKind, BinOpKind, ChildSlice, LexError, Lexer, Node, NodeData,
    NodeId, NodeKind, ParsedAst, Span, Symbol, SymbolTable, Token, TokenKind, UnaryOpKind,
};

const BP_IMPL: u8 = 20;
const BP_OR: u8 = 30;
const BP_AND: u8 = 40;
const BP_EQ: u8 = 50;
const BP_COMPARE: u8 = 60;
const BP_UPDATE: u8 = 70;
const BP_NOT_PREFIX: u8 = 80;
const BP_ADD: u8 = 90;
const BP_MUL: u8 = 100;
const BP_CONCAT: u8 = 110;
const BP_HAS_ATTR: u8 = 120;
const BP_NEG_PREFIX: u8 = 130;
const BP_APPLY: u8 = 140;
const BP_SELECT: u8 = 150;
const FORMAL_LOOKAHEAD_LIMIT: usize = 4096;
const INDENT_INFINITY: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StringSyntax {
    Double,
    Indented,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StringFragment {
    Literal {
        span: Span,
        bytes: Vec<u8>,
        has_indentation: bool,
    },
    Interpolation(NodeId),
}

/// Parses a UTF-8 Nix source string into an AST.
///
/// # Errors
///
/// Returns [`ParseError`] when lexing fails, when the token stream is not valid
/// Nix syntax for the implemented grammar, or when arena/symbol allocation
/// exceeds `u32` addressability.
pub fn parse_str(source: &str) -> Result<ParsedAst, ParseError> {
    Parser::from_source_str(source).parse()
}

/// Parses a UTF-8 Nix source string using an existing symbol table.
///
/// This entry point lets callers thread one append-only table across multiple
/// source files while preserving the default [`parse_str`] convenience API for
/// isolated parses. The table is consumed and returned in [`ParsedAst`] only on
/// success; speculative callers that need rollback should clone the table before
/// parsing.
///
/// # Errors
///
/// Returns [`ParseError`] when lexing fails, when the token stream is not valid
/// Nix syntax for the implemented grammar, or when arena/symbol allocation
/// exceeds `u32` addressability.
pub fn parse_str_with_symbols(source: &str, symbols: SymbolTable) -> Result<ParsedAst, ParseError> {
    Parser::from_source_str_with_symbols(source, symbols).parse()
}

/// Parses Nix source bytes into an AST.
///
/// # Errors
///
/// Returns [`ParseError`] when lexing fails, when the token stream is not valid
/// Nix syntax for the implemented grammar, or when arena/symbol allocation
/// exceeds `u32` addressability.
pub fn parse_bytes(source: &[u8]) -> Result<ParsedAst, ParseError> {
    Parser::new(source).parse()
}

/// Parses Nix source bytes using an existing symbol table.
///
/// The table is consumed and returned in [`ParsedAst`] only on success;
/// speculative callers that need rollback should clone the table before
/// parsing.
///
/// # Errors
///
/// Returns [`ParseError`] when lexing fails, when the token stream is not valid
/// Nix syntax for the implemented grammar, or when arena/symbol allocation
/// exceeds `u32` addressability.
pub fn parse_bytes_with_symbols(
    source: &[u8],
    symbols: SymbolTable,
) -> Result<ParsedAst, ParseError> {
    Parser::with_symbols(source, symbols).parse()
}

/// A hand-written Nix parser.
#[derive(Clone, Debug)]
pub struct Parser<'a> {
    source: &'a [u8],
    lexer: Lexer<'a>,
    lookahead: Option<Token>,
    arena: AstArena,
    symbols: SymbolTable,
}

impl<'a> Parser<'a> {
    /// Creates a parser over source bytes.
    pub fn new(source: &'a [u8]) -> Self {
        Self::with_symbols(source, SymbolTable::new())
    }

    /// Creates a parser over source bytes using an existing symbol table.
    pub fn with_symbols(source: &'a [u8], symbols: SymbolTable) -> Self {
        Self {
            source,
            lexer: Lexer::new(source),
            lookahead: None,
            arena: AstArena::new(),
            symbols,
        }
    }

    /// Creates a parser over a UTF-8 source string.
    pub fn from_source_str(source: &'a str) -> Self {
        Self::new(source.as_bytes())
    }

    /// Creates a parser over a UTF-8 source string using an existing symbol
    /// table.
    pub fn from_source_str_with_symbols(source: &'a str, symbols: SymbolTable) -> Self {
        Self::with_symbols(source.as_bytes(), symbols)
    }

    /// Parses the full source and requires end-of-file after the root
    /// expression.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when lexing fails, when syntax is invalid, or
    /// when arena/symbol allocation exceeds `u32` addressability.
    pub fn parse(mut self) -> Result<ParsedAst, ParseError> {
        let root = self.parse_expr()?;
        let eof = self.peek()?;
        if eof.kind != TokenKind::Eof {
            return Err(self.error_at(
                eof.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "end of file",
                    found: eof.kind,
                },
            ));
        }

        Ok(ParsedAst::new(root, self.arena, self.symbols))
    }

    fn parse_expr(&mut self) -> Result<NodeId, ParseError> {
        let token = self.peek()?;
        match token.kind {
            TokenKind::Let => self.parse_let_in(),
            TokenKind::With => self.parse_with(),
            TokenKind::Assert => self.parse_assert(),
            TokenKind::If => self.parse_if(),
            TokenKind::Ident if self.peek_second_kind()? == TokenKind::Colon => {
                self.parse_simple_lambda()
            }
            TokenKind::Ident if self.starts_prefixed_formal_lambda()? => {
                self.parse_prefixed_formal_lambda()
            }
            TokenKind::LBrace if self.starts_formal_lambda()? => self.parse_formal_lambda(None),
            _ => self.parse_pratt(0),
        }
    }

    fn parse_let_in(&mut self) -> Result<NodeId, ParseError> {
        let start = self.expect(TokenKind::Let)?.span;
        let bindings = self.parse_bindings_until(TokenKind::In)?;
        self.expect(TokenKind::In)?;
        let body = self.parse_expr()?;
        let span = self.join_span(start, self.node_span(body)?);
        self.push(NodeKind::LetIn, span, NodeData::LetIn { bindings, body })
    }

    fn parse_with(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_assert(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_if(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_simple_lambda(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_prefixed_formal_lambda(&mut self) -> Result<NodeId, ParseError> {
        let alias_token = self.expect_symbol_token()?;
        let alias = self.intern_token(alias_token)?;
        self.expect(TokenKind::At)?;
        self.parse_formal_lambda(Some(alias))
    }

    fn parse_formal_lambda(&mut self, prefix_alias: Option<Symbol>) -> Result<NodeId, ParseError> {
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

    fn parse_formal_set(&mut self, prefix_alias: Option<Symbol>) -> Result<NodeId, ParseError> {
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
            alias = Some(self.intern_token(alias_token)?);
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

    fn parse_pratt(&mut self, min_bp: u8) -> Result<NodeId, ParseError> {
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

    fn parse_prefix(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_primary(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_select_expr(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_int(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_float(&mut self) -> Result<NodeId, ParseError> {
        let token = self.expect(TokenKind::Float)?;
        let text = self.token_text(token)?;
        let value = text.parse::<f64>().map_err(|_| {
            self.error_at(token.span, ParseErrorKind::InvalidLiteral { kind: "float" })
        })?;
        self.push(NodeKind::Float, token.span, NodeData::Float(value))
    }

    fn parse_identifier_node(&mut self) -> Result<NodeId, ParseError> {
        let token = self.expect(TokenKind::Ident)?;
        let symbol = self.intern_token(token)?;
        self.push(NodeKind::Ident, token.span, NodeData::Symbol(symbol))
    }

    fn parse_symbol_node(&mut self, kind: NodeKind) -> Result<NodeId, ParseError> {
        let token = self.expect_symbol_like()?;
        let symbol = self.intern_token(token)?;
        self.push(kind, token.span, NodeData::Symbol(symbol))
    }

    fn parse_attr_symbol_node(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_path(&mut self) -> Result<NodeId, ParseError> {
        let first = self.expect(TokenKind::Path)?;
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
                    fragments.push(self.push(
                        NodeKind::Interp,
                        self.join_span(start, close),
                        NodeData::Node(expr),
                    )?);
                }
                TokenKind::Path => {
                    let token = self.bump()?;
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

    fn parse_paren(&mut self) -> Result<NodeId, ParseError> {
        self.expect(TokenKind::LParen)?;
        let expr = self.parse_expr()?;
        self.expect(TokenKind::RParen)?;
        Ok(expr)
    }

    fn parse_list(&mut self) -> Result<NodeId, ParseError> {
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

    fn parse_rec_attrset(&mut self) -> Result<NodeId, ParseError> {
        self.expect(TokenKind::Rec)?;
        self.parse_attrset(true)
    }

    fn parse_attrset(&mut self, recursive: bool) -> Result<NodeId, ParseError> {
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

    fn parse_bindings_until(&mut self, terminator: TokenKind) -> Result<ChildSlice, ParseError> {
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

    fn parse_binding(&mut self) -> Result<Vec<NodeId>, ParseError> {
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

    fn parse_inherit(&mut self) -> Result<Vec<NodeId>, ParseError> {
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

    fn parse_attr_path(&mut self) -> Result<ChildSlice, ParseError> {
        let mut segments = vec![self.parse_attr_segment()?];
        while self.peek()?.kind == TokenKind::Dot {
            self.bump()?;
            segments.push(self.parse_attr_segment()?);
        }
        self.push_child_slice(&segments)
    }

    fn normalize_bindings(&mut self, bindings: Vec<NodeId>) -> Result<Vec<NodeId>, ParseError> {
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

    fn normalize_binding_path(&mut self, binding: NodeId) -> Result<NodeId, ParseError> {
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

    fn nested_binding(
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
            let nested = self.nested_binding(tail, value, None)?;
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

    fn merge_binding_nodes(
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

        let value =
            self.merge_binding_values(existing_value, incoming_value, incoming_node.span)?;
        self.push(
            NodeKind::Binding,
            self.join_span(existing_node.span, incoming_node.span),
            NodeData::Binding { path, value },
        )
    }

    fn merge_binding_values(
        &mut self,
        existing: NodeId,
        incoming: NodeId,
        conflict_span: Span,
    ) -> Result<NodeId, ParseError> {
        let existing_node = self.node(existing)?;
        let incoming_node = self.node(incoming)?;
        if !Self::is_attrset_kind(existing_node.kind) || !Self::is_attrset_kind(incoming_node.kind)
        {
            return Err(self.error_at(conflict_span, ParseErrorKind::DuplicateAttribute));
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

    fn binding_target_symbol(&self, binding: NodeId) -> Result<Option<Symbol>, ParseError> {
        let node = self.node(binding)?;
        let NodeData::Binding { path, .. } = node.data else {
            return Ok(None);
        };
        let Some(segment) = self.child_ids(path)?.first().copied() else {
            return Ok(None);
        };
        self.static_attr_symbol(segment)
    }

    fn static_attr_symbol(&self, node: NodeId) -> Result<Option<Symbol>, ParseError> {
        let node = self.node(node)?;
        match node.kind {
            NodeKind::Ident | NodeKind::Str => self.symbol_payload(node).map(Some),
            _ => Ok(None),
        }
    }

    fn symbol_payload(&self, node: Node) -> Result<Symbol, ParseError> {
        let NodeData::Symbol(symbol) = node.data else {
            return Err(self.error_at(node.span, ParseErrorKind::InvalidBindingPath));
        };
        Ok(symbol)
    }

    fn is_attrset_kind(kind: NodeKind) -> bool {
        matches!(kind, NodeKind::AttrSet | NodeKind::RecAttrSet)
    }

    fn parse_attr_segment(&mut self) -> Result<NodeId, ParseError> {
        let token = self.peek()?;
        match token.kind {
            TokenKind::Ident | TokenKind::Or => self.parse_attr_symbol_node(),
            TokenKind::StrStart => {
                self.parse_string(TokenKind::StrEnd, NodeKind::Str, StringSyntax::Double)
            }
            TokenKind::IndStrStart => {
                self.parse_string(TokenKind::IndStrEnd, NodeKind::Str, StringSyntax::Indented)
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

    fn parse_string(
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

    fn materialize_string_fragments(
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

    fn flush_string_literal(
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

    fn starts_application_arg(&self, kind: TokenKind) -> bool {
        matches!(
            kind,
            TokenKind::Int
                | TokenKind::Float
                | TokenKind::Ident
                | TokenKind::Or
                | TokenKind::Path
                | TokenKind::SPath
                | TokenKind::Uri
                | TokenKind::StrStart
                | TokenKind::IndStrStart
                | TokenKind::LParen
                | TokenKind::LBracket
                | TokenKind::LBrace
                | TokenKind::Rec
        )
    }

    fn starts_prefixed_formal_lambda(&mut self) -> Result<bool, ParseError> {
        let mut probe = self.probe();
        if probe.bump()?.kind != TokenKind::Ident {
            return Ok(false);
        }
        Ok(probe.bump()?.kind == TokenKind::At && probe.bump()?.kind == TokenKind::LBrace)
    }

    fn starts_formal_lambda(&mut self) -> Result<bool, ParseError> {
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

    fn peek_second_kind(&mut self) -> Result<TokenKind, ParseError> {
        let mut probe = self.probe();
        probe.bump()?;
        Ok(probe.peek()?.kind)
    }

    fn peek(&mut self) -> Result<Token, ParseError> {
        if self.lookahead.is_none() {
            self.lookahead = Some(next_significant(&mut self.lexer)?);
        }
        self.lookahead.ok_or_else(|| {
            self.error_at(
                Span::new(u32::MAX, u32::MAX),
                ParseErrorKind::UnexpectedToken {
                    expected: "token",
                    found: TokenKind::Eof,
                },
            )
        })
    }

    fn bump(&mut self) -> Result<Token, ParseError> {
        if let Some(token) = self.lookahead.take() {
            return Ok(token);
        }
        next_significant(&mut self.lexer)
    }

    fn expect(&mut self, kind: TokenKind) -> Result<Token, ParseError> {
        let token = self.bump()?;
        if token.kind == kind {
            Ok(token)
        } else {
            Err(self.error_at(
                token.span,
                ParseErrorKind::UnexpectedToken {
                    expected: token_name(kind),
                    found: token.kind,
                },
            ))
        }
    }

    fn expect_symbol_token(&mut self) -> Result<Token, ParseError> {
        let token = self.bump()?;
        if token.kind == TokenKind::Ident {
            Ok(token)
        } else {
            Err(self.error_at(
                token.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "identifier",
                    found: token.kind,
                },
            ))
        }
    }

    fn expect_symbol_like(&mut self) -> Result<Token, ParseError> {
        let token = self.bump()?;
        if matches!(
            token.kind,
            TokenKind::Ident | TokenKind::Path | TokenKind::SPath | TokenKind::Uri
        ) {
            Ok(token)
        } else {
            Err(self.error_at(
                token.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "symbol-like token",
                    found: token.kind,
                },
            ))
        }
    }

    fn push(&mut self, kind: NodeKind, span: Span, data: NodeData) -> Result<NodeId, ParseError> {
        self.arena
            .push_node(kind, span, data)
            .map_err(ParseError::from_ast)
    }

    fn push_child_slice(&mut self, children: &[NodeId]) -> Result<ChildSlice, ParseError> {
        self.arena
            .push_child_slice(children)
            .map_err(ParseError::from_ast)
    }

    fn intern_token(&mut self, token: Token) -> Result<Symbol, ParseError> {
        let bytes = self.token_bytes(token)?;
        self.intern_bytes(bytes)
    }

    fn intern_bytes(&mut self, bytes: &[u8]) -> Result<Symbol, ParseError> {
        self.symbols.intern(bytes).map_err(ParseError::from_ast)
    }

    fn token_bytes(&self, token: Token) -> Result<&'a [u8], ParseError> {
        let start = token.span.start as usize;
        let end = token.span.end as usize;
        self.source.get(start..end).ok_or_else(|| {
            self.error_at(
                token.span,
                ParseErrorKind::InvalidSpan {
                    start: token.span.start,
                    end: token.span.end,
                },
            )
        })
    }

    fn token_text(&self, token: Token) -> Result<&'a str, ParseError> {
        str::from_utf8(self.token_bytes(token)?)
            .map_err(|_| self.error_at(token.span, ParseErrorKind::InvalidUtf8Literal))
    }

    fn node(&self, node: NodeId) -> Result<Node, ParseError> {
        self.arena.node(node).copied().ok_or_else(|| {
            self.error_at(
                Span::new(u32::MAX, u32::MAX),
                ParseErrorKind::InvalidNodeId(node.as_u32()),
            )
        })
    }

    fn child_ids(&self, slice: ChildSlice) -> Result<Vec<NodeId>, ParseError> {
        Ok(self
            .arena
            .child_slice(slice)
            .map_err(ParseError::from_ast)?
            .to_vec())
    }

    fn node_span(&self, node: NodeId) -> Result<Span, ParseError> {
        self.arena.node(node).map(|node| node.span).ok_or_else(|| {
            self.error_at(
                Span::new(u32::MAX, u32::MAX),
                ParseErrorKind::InvalidNodeId(node.as_u32()),
            )
        })
    }

    fn slice_span(&self, slice: ChildSlice) -> Span {
        let Ok(children) = self.arena.child_slice(slice) else {
            return Span::new(u32::MAX, u32::MAX);
        };
        let Some(first) = children.first().and_then(|node| self.arena.node(*node)) else {
            return Span::new(u32::MAX, u32::MAX);
        };
        let Some(last) = children.last().and_then(|node| self.arena.node(*node)) else {
            return first.span;
        };
        self.join_span(first.span, last.span)
    }

    fn join_span(&self, first: Span, second: Span) -> Span {
        Span::new(first.start.min(second.start), first.end.max(second.end))
    }

    fn error_at(&self, span: Span, kind: ParseErrorKind) -> ParseError {
        ParseError::new(kind, span)
    }

    fn probe(&self) -> TokenProbe<'a> {
        TokenProbe {
            lexer: self.lexer.clone(),
            lookahead: self.lookahead,
        }
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

#[derive(Clone, Debug)]
struct TokenProbe<'a> {
    lexer: Lexer<'a>,
    lookahead: Option<Token>,
}

impl TokenProbe<'_> {
    fn peek(&mut self) -> Result<Token, ParseError> {
        if self.lookahead.is_none() {
            self.lookahead = Some(next_significant(&mut self.lexer)?);
        }
        self.lookahead.ok_or_else(|| {
            ParseError::new(
                ParseErrorKind::UnexpectedToken {
                    expected: "token",
                    found: TokenKind::Eof,
                },
                Span::new(u32::MAX, u32::MAX),
            )
        })
    }

    fn bump(&mut self) -> Result<Token, ParseError> {
        if let Some(token) = self.lookahead.take() {
            return Ok(token);
        }
        next_significant(&mut self.lexer)
    }

    fn consume_formal_set_shape(&mut self) -> Result<bool, ParseError> {
        if self.bump()?.kind != TokenKind::LBrace {
            return Ok(false);
        }

        let mut steps = 0usize;
        let mut expect_formal = true;
        let mut saw_ellipsis = false;

        loop {
            steps += 1;
            if steps > FORMAL_LOOKAHEAD_LIMIT {
                return Ok(false);
            }

            let token = self.peek()?;
            match token.kind {
                TokenKind::RBrace => {
                    self.bump()?;
                    return Ok(true);
                }
                TokenKind::Ident if expect_formal && !saw_ellipsis => {
                    self.bump()?;
                    if self.peek()?.kind == TokenKind::Question {
                        self.bump()?;
                        self.skip_default_expr()?;
                    }
                    expect_formal = false;
                }
                TokenKind::Ellipsis if expect_formal && !saw_ellipsis => {
                    self.bump()?;
                    saw_ellipsis = true;
                    expect_formal = false;
                }
                TokenKind::Comma if !expect_formal => {
                    if saw_ellipsis {
                        return Ok(false);
                    }
                    self.bump()?;
                    expect_formal = true;
                }
                _ => return Ok(false),
            }
        }
    }

    fn skip_default_expr(&mut self) -> Result<(), ParseError> {
        let mut parens = 0u32;
        let mut braces = 0u32;
        let mut brackets = 0u32;
        let mut interpolation = 0u32;

        for _ in 0..FORMAL_LOOKAHEAD_LIMIT {
            let token = self.peek()?;
            match token.kind {
                TokenKind::Comma | TokenKind::RBrace
                    if parens == 0 && braces == 0 && brackets == 0 && interpolation == 0 =>
                {
                    return Ok(());
                }
                TokenKind::DollarBrace => interpolation = interpolation.saturating_add(1),
                TokenKind::LParen => parens = parens.saturating_add(1),
                TokenKind::RParen if parens > 0 => parens -= 1,
                TokenKind::LBrace => braces = braces.saturating_add(1),
                TokenKind::RBrace if interpolation > 0 => interpolation -= 1,
                TokenKind::RBrace if braces > 0 => braces -= 1,
                TokenKind::LBracket => brackets = brackets.saturating_add(1),
                TokenKind::RBracket if brackets > 0 => brackets -= 1,
                TokenKind::Eof => return Ok(()),
                _ => {}
            }
            self.bump()?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Infix {
    kind: BinOpKind,
    left_bp: u8,
    right_bp: u8,
    assoc: Assoc,
    name: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Assoc {
    Left,
    Right,
    None,
}

fn infix_operator(kind: TokenKind) -> Option<Infix> {
    let infix = match kind {
        TokenKind::Concat => Infix::right(BinOpKind::Concat, BP_CONCAT, "++"),
        TokenKind::Star => Infix::left(BinOpKind::Mul, BP_MUL, "*"),
        TokenKind::Slash => Infix::left(BinOpKind::Div, BP_MUL, "/"),
        TokenKind::Plus => Infix::left(BinOpKind::Add, BP_ADD, "+"),
        TokenKind::Minus => Infix::left(BinOpKind::Sub, BP_ADD, "-"),
        TokenKind::Update => Infix::right(BinOpKind::Update, BP_UPDATE, "//"),
        TokenKind::Less => Infix::none(BinOpKind::Lt, BP_COMPARE, "<"),
        TokenKind::Greater => Infix::none(BinOpKind::Gt, BP_COMPARE, ">"),
        TokenKind::LessEq => Infix::none(BinOpKind::Le, BP_COMPARE, "<="),
        TokenKind::GreaterEq => Infix::none(BinOpKind::Ge, BP_COMPARE, ">="),
        TokenKind::EqEq => Infix::none(BinOpKind::Eq, BP_EQ, "=="),
        TokenKind::NotEq => Infix::none(BinOpKind::Ne, BP_EQ, "!="),
        TokenKind::And => Infix::left(BinOpKind::And, BP_AND, "&&"),
        TokenKind::OrOr => Infix::left(BinOpKind::Or, BP_OR, "||"),
        TokenKind::Impl => Infix::right(BinOpKind::Impl, BP_IMPL, "->"),
        _ => return None,
    };
    Some(infix)
}

impl Infix {
    const fn left(kind: BinOpKind, bp: u8, name: &'static str) -> Self {
        Self {
            kind,
            left_bp: bp,
            right_bp: bp + 1,
            assoc: Assoc::Left,
            name,
        }
    }

    const fn right(kind: BinOpKind, bp: u8, name: &'static str) -> Self {
        Self {
            kind,
            left_bp: bp,
            right_bp: bp,
            assoc: Assoc::Right,
            name,
        }
    }

    const fn none(kind: BinOpKind, bp: u8, name: &'static str) -> Self {
        Self {
            kind,
            left_bp: bp,
            right_bp: bp + 1,
            assoc: Assoc::None,
            name,
        }
    }
}

fn next_significant(lexer: &mut Lexer<'_>) -> Result<Token, ParseError> {
    loop {
        let token = lexer.next_token().map_err(ParseError::from_lex)?;
        if !token.kind.is_trivia() {
            return Ok(token);
        }
    }
}

fn token_name(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Let => "let",
        TokenKind::In => "in",
        TokenKind::If => "if",
        TokenKind::Then => "then",
        TokenKind::Else => "else",
        TokenKind::With => "with",
        TokenKind::Assert => "assert",
        TokenKind::Colon => ":",
        TokenKind::Semi => ";",
        TokenKind::Comma => ",",
        TokenKind::Assign => "=",
        TokenKind::RBrace => "}",
        TokenKind::RBracket => "]",
        TokenKind::RParen => ")",
        _ => "token",
    }
}

/// A parser failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{kind} at byte span {span:?}")]
pub struct ParseError {
    kind: ParseErrorKind,
    span: Span,
}

impl ParseError {
    /// Creates a parser error.
    pub const fn new(kind: ParseErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Returns the error category.
    pub const fn kind(&self) -> &ParseErrorKind {
        &self.kind
    }

    /// Returns the source span associated with the error.
    pub const fn span(&self) -> Span {
        self.span
    }

    fn from_lex(error: LexError) -> Self {
        Self::new(ParseErrorKind::Lex(error.kind().clone()), error.span())
    }

    fn from_ast(error: AstError) -> Self {
        Self::new(ParseErrorKind::Ast(error.kind().clone()), error.span())
    }
}

/// The category of a parser failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// Lexing failed before parsing could continue.
    #[error("lexer error: {0}")]
    Lex(super::LexErrorKind),
    /// AST arena or symbol allocation failed.
    #[error("AST arena error: {0}")]
    Ast(AstErrorKind),
    /// The parser found a token that cannot appear in the current position.
    #[error("expected {expected}, found {found:?}")]
    UnexpectedToken {
        /// The syntactic item expected at this point.
        expected: &'static str,
        /// The token kind that was found.
        found: TokenKind,
    },
    /// A literal token could not be decoded as the expected literal kind.
    #[error("invalid {kind} literal")]
    InvalidLiteral {
        /// The literal category.
        kind: &'static str,
    },
    /// A literal that should be ASCII/UTF-8 was not valid UTF-8.
    #[error("invalid UTF-8 literal")]
    InvalidUtf8Literal,
    /// A stored token span did not point into the parser's source.
    #[error("invalid source span {start}..{end}")]
    InvalidSpan {
        /// The invalid start byte.
        start: u32,
        /// The invalid end byte.
        end: u32,
    },
    /// A parser-created node id did not exist in the arena.
    #[error("invalid AST node id {0}")]
    InvalidNodeId(u32),
    /// A non-associative operator was chained at parse time.
    #[error("non-associative operator {operator} cannot be chained")]
    NonAssociativeOperator {
        /// The operator spelling.
        operator: &'static str,
    },
    /// A binding path could not be normalized into parser-side bindings.
    #[error("invalid binding path")]
    InvalidBindingPath,
    /// Two bindings define the same non-mergeable attribute.
    #[error("attribute already defined")]
    DuplicateAttribute,
    /// A formal argument pattern violates Nix's shape restrictions.
    #[error("invalid formal argument pattern: {reason}")]
    InvalidFormalPattern {
        /// The violated formal-pattern rule.
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> ParsedAst {
        parse_str(source).expect("source parses")
    }

    fn node(ast: &ParsedAst, id: NodeId) -> &super::super::Node {
        ast.arena.node(id).expect("node exists")
    }

    fn string_bytes(ast: &ParsedAst, id: NodeId) -> &[u8] {
        let NodeData::Symbol(symbol) = node(ast, id).data else {
            panic!("string node should carry a symbol");
        };
        ast.symbols.resolve(symbol).expect("string symbol resolves")
    }

    fn child_ids(ast: &ParsedAst, slice: ChildSlice) -> &[NodeId] {
        ast.arena.child_slice(slice).expect("child slice exists")
    }

    fn binding_path_and_value(ast: &ParsedAst, binding: NodeId) -> (&[NodeId], NodeId) {
        let NodeData::Binding { path, value } = node(ast, binding).data else {
            panic!("binding payload expected");
        };
        (child_ids(ast, path), value)
    }

    fn binding_name<'a>(ast: &'a ParsedAst, binding: NodeId) -> &'a [u8] {
        let (path, _) = binding_path_and_value(ast, binding);
        assert_eq!(path.len(), 1);
        let NodeData::Symbol(symbol) = node(ast, path[0]).data else {
            panic!("binding path should carry a symbol");
        };
        ast.symbols.resolve(symbol).expect("symbol resolves")
    }

    #[test]
    fn parses_let_lambda_application_skeleton() {
        let ast = parse("let x = 1; f = y: x + y; in f 41");
        let root = node(&ast, ast.root);
        assert_eq!(root.kind, NodeKind::LetIn);

        let NodeData::LetIn { bindings, body } = root.data else {
            panic!("root should carry let-in data");
        };
        assert_eq!(ast.arena.child_slice(bindings).expect("bindings").len(), 2);
        assert_eq!(node(&ast, body).kind, NodeKind::Apply);
    }

    #[test]
    fn parser_can_thread_shared_symbol_table_across_files() {
        let first = parse("alpha");
        let second = parse_str_with_symbols("beta", first.symbols).expect("second source parses");

        assert_eq!(
            second.symbols.resolve(Symbol::new(0)),
            Some(b"alpha".as_slice())
        );
        assert_eq!(
            second.symbols.resolve(Symbol::new(1)),
            Some(b"beta".as_slice())
        );

        let NodeData::Symbol(symbol) = node(&second, second.root).data else {
            panic!("root should be an identifier symbol");
        };
        assert_eq!(symbol.as_u32(), 1);

        let third = parse_str_with_symbols("alpha", second.symbols).expect("third source parses");
        let NodeData::Symbol(symbol) = node(&third, third.root).data else {
            panic!("root should be an identifier symbol");
        };
        assert_eq!(symbol.as_u32(), 0);

        let isolated = parse("beta");
        assert_eq!(
            isolated.symbols.resolve(Symbol::new(0)),
            Some(b"beta".as_slice())
        );
    }

    #[test]
    fn pratt_parser_honors_multiplicative_precedence() {
        let ast = parse("1 + 2 * 3");
        let root = node(&ast, ast.root);
        let NodeData::Binary { op, rhs, .. } = root.data else {
            panic!("root should be binary");
        };
        assert_eq!(op, BinOpKind::Add);
        assert_eq!(node(&ast, rhs).kind, NodeKind::BinOp);
        let NodeData::Binary { op: rhs_op, .. } = node(&ast, rhs).data else {
            panic!("rhs should be binary");
        };
        assert_eq!(rhs_op, BinOpKind::Mul);
    }

    #[test]
    fn rejects_non_associative_equality_chains() {
        let error = parse_str("a == b == c").expect_err("equality chaining is rejected");
        assert_eq!(
            error.kind(),
            &ParseErrorKind::NonAssociativeOperator { operator: "==" }
        );
    }

    #[test]
    fn reports_first_significant_error_after_skipped_trivia() {
        let source = "let x = 1;\n  @@@\nin x";
        let error = parse_str(source).expect_err("invalid binding errors");
        let start = source.find('@').expect("source contains bad token") as u32;
        assert_eq!(error.span(), Span::new(start, start + 1));
        assert!(matches!(
            error.kind(),
            ParseErrorKind::UnexpectedToken {
                found: TokenKind::At,
                ..
            }
        ));
    }

    #[test]
    fn parses_select_defaults_and_has_attr_paths() {
        let ast = parse("pkg.meta.name or fallback");
        let root = node(&ast, ast.root);
        assert_eq!(root.kind, NodeKind::Select);
        let NodeData::Select { path, default, .. } = root.data else {
            panic!("select data expected");
        };
        assert!(default.is_some());
        assert_eq!(ast.arena.child_slice(path).expect("path").len(), 2);

        let ast = parse("pkg ? meta.name");
        let root = node(&ast, ast.root);
        assert_eq!(root.kind, NodeKind::HasAttr);
    }

    #[test]
    fn contextual_or_matches_pinned_keyword_positions() {
        parse("({ or = 1; }).or");
        parse("({ missing = 1; }).or or 2");
        parse("let or = 1; in 0");
        parse("let inherit ({ or = 1; }) or; in 0");
        parse("let f = x: x; or = 2; in f or");
        parse("let f = x: x; or = { a = 1; }; in f or ? a");

        for source in [
            "or",
            "(or)",
            "[ or ]",
            "if or then 1 else 0",
            "assert or; 1",
            "or: 1",
            "or@{ a }: 1",
            "{ a }@or: 1",
            "{ or }: 1",
            "{ or ? 1 }: 1",
            "let f = x: x; or = { a = 1; }; in f or.a",
            "let f = x: x; or = { a = 1; }; in f or or 2",
        ] {
            parse_str(source).expect_err("contextual or position should match pinned Nix");
        }
    }

    #[test]
    fn parse_fail_lexical_rejections_are_reported() {
        for source in [
            "\"unterminated",
            "''unterminated",
            "/* unterminated",
            "*/",
            "999999999999999999999999",
        ] {
            parse_str(source).expect_err("malformed lexical input should be rejected");
        }
    }

    #[test]
    fn semicolon_is_not_a_general_expression_terminator() {
        parse("let x = 1; in x");
        parse("{ x = 1; }");
        parse("assert true; 1");
        parse("with { x = 1; }; x");

        for source in ["1;", "[ 1; ]", "(1;)"] {
            parse_str(source).expect_err("semicolon is not a general expression terminator");
        }
    }

    #[test]
    fn select_defaults_bind_tighter_than_application_and_operators() {
        let ast = parse("({ a = 10; }).a or 1 * 2");
        let root = node(&ast, ast.root);
        let NodeData::Binary { op, lhs, .. } = root.data else {
            panic!("root should be binary");
        };
        assert_eq!(op, BinOpKind::Mul);
        assert_eq!(node(&ast, lhs).kind, NodeKind::Select);

        let ast = parse("f.a or g 1");
        let root = node(&ast, ast.root);
        assert_eq!(root.kind, NodeKind::Apply);
        let NodeData::Pair { first, .. } = root.data else {
            panic!("apply pair expected");
        };
        assert_eq!(node(&ast, first).kind, NodeKind::Select);
    }

    #[test]
    fn parses_formal_lambda_with_bounded_lookahead() {
        let ast = parse("{ a, b ? 1, ... }@args: a");
        let root = node(&ast, ast.root);
        assert_eq!(root.kind, NodeKind::Lambda);
        let NodeData::Pair { first, .. } = root.data else {
            panic!("lambda pair expected");
        };
        assert_eq!(node(&ast, first).kind, NodeKind::FormalSet);
        let NodeData::FormalSet {
            formals,
            ellipsis,
            alias,
        } = node(&ast, first).data
        else {
            panic!("formal set data expected");
        };
        assert!(ellipsis);
        assert!(alias.is_some());
        assert_eq!(ast.arena.child_slice(formals).expect("formals").len(), 2);
    }

    #[test]
    fn formal_lookahead_handles_interpolated_defaults() {
        parse("{ a ? \"${x}\" }: a");
        parse("{ a ? ./x/${name} }: a");
    }

    #[test]
    fn rejects_invalid_formal_patterns() {
        for source in ["{ ..., a }: a", "{ a, ..., b }: a", "args@{}@more: args"] {
            let error = parse_str(source).expect_err("invalid formal pattern");
            assert!(matches!(
                error.kind(),
                ParseErrorKind::InvalidFormalPattern { .. }
                    | ParseErrorKind::UnexpectedToken { .. }
            ));
        }

        for source in ["{ ..., }: 1", "{ a, ..., }: a", "{ a, a }: a"] {
            let error = parse_str(source).expect_err("invalid formal pattern");
            assert!(matches!(
                error.kind(),
                ParseErrorKind::InvalidFormalPattern { .. }
                    | ParseErrorKind::UnexpectedToken { .. }
            ));
        }
    }

    #[test]
    fn parses_attrsets_lists_and_inherit() {
        let ast = parse("{ inherit (src) name version; list = [ 1 2 3 ]; }");
        let root = node(&ast, ast.root);
        assert_eq!(root.kind, NodeKind::AttrSet);
        let NodeData::Children(bindings) = root.data else {
            panic!("attrset children expected");
        };
        let bindings = ast.arena.child_slice(bindings).expect("bindings");
        assert_eq!(bindings.len(), 3);
        assert_eq!(node(&ast, bindings[0]).kind, NodeKind::Binding);
        assert_eq!(node(&ast, bindings[1]).kind, NodeKind::Binding);
        assert_eq!(node(&ast, bindings[2]).kind, NodeKind::Binding);
        assert_eq!(binding_name(&ast, bindings[0]), b"name");
        assert_eq!(binding_name(&ast, bindings[1]), b"version");
        assert_eq!(binding_name(&ast, bindings[2]), b"list");

        let (_, value) = binding_path_and_value(&ast, bindings[0]);
        assert_eq!(node(&ast, value).kind, NodeKind::Inherit);
    }

    #[test]
    fn empty_inherit_groups_desugar_to_no_bindings() {
        let ast = parse("{ inherit; x = 1; }");
        let NodeData::Children(bindings) = node(&ast, ast.root).data else {
            panic!("attrset children expected");
        };
        let bindings = child_ids(&ast, bindings);
        assert_eq!(bindings.len(), 1);
        assert_eq!(binding_name(&ast, bindings[0]), b"x");
    }

    #[test]
    fn empty_inherit_from_groups_keep_a_scope_marker() {
        let ast = parse("{ inherit (src); x = 1; }");
        let NodeData::Children(bindings) = node(&ast, ast.root).data else {
            panic!("attrset children expected");
        };
        let bindings = child_ids(&ast, bindings);
        assert_eq!(bindings.len(), 2);
        assert_eq!(node(&ast, bindings[0]).kind, NodeKind::Inherit);
        assert_eq!(binding_name(&ast, bindings[1]), b"x");
    }

    #[test]
    fn inherit_from_bindings_share_the_source_expression() {
        let ast = parse("{ inherit (src) name version; }");
        let NodeData::Children(bindings) = node(&ast, ast.root).data else {
            panic!("attrset children expected");
        };
        let bindings = child_ids(&ast, bindings);
        assert_eq!(bindings.len(), 2);

        let (_, first_value) = binding_path_and_value(&ast, bindings[0]);
        let (_, second_value) = binding_path_and_value(&ast, bindings[1]);
        let NodeData::Inherit {
            from: Some(first_from),
            ..
        } = node(&ast, first_value).data
        else {
            panic!("first inherit marker expected");
        };
        let NodeData::Inherit {
            from: Some(second_from),
            ..
        } = node(&ast, second_value).data
        else {
            panic!("second inherit marker expected");
        };
        assert_eq!(first_from, second_from);
    }

    #[test]
    fn merges_static_attr_path_bindings_into_nested_attrsets() {
        let ast = parse("{ a.b = 1; a.c = 2; }");
        let root = node(&ast, ast.root);
        let NodeData::Children(bindings) = root.data else {
            panic!("attrset children expected");
        };
        let bindings = child_ids(&ast, bindings);
        assert_eq!(bindings.len(), 1);
        assert_eq!(binding_name(&ast, bindings[0]), b"a");

        let (_, nested) = binding_path_and_value(&ast, bindings[0]);
        assert_eq!(node(&ast, nested).kind, NodeKind::AttrSet);
        let NodeData::Children(nested_bindings) = node(&ast, nested).data else {
            panic!("nested attrset children expected");
        };
        let nested_bindings = child_ids(&ast, nested_bindings);
        assert_eq!(nested_bindings.len(), 2);
        assert_eq!(binding_name(&ast, nested_bindings[0]), b"b");
        assert_eq!(binding_name(&ast, nested_bindings[1]), b"c");
    }

    #[test]
    fn attr_path_bindings_normalize_let_bindings_too() {
        let ast = parse("let a.b = 1; a.c = 2; in a");
        let NodeData::LetIn { bindings, .. } = node(&ast, ast.root).data else {
            panic!("let-in payload expected");
        };
        let bindings = child_ids(&ast, bindings);
        assert_eq!(bindings.len(), 1);
        assert_eq!(binding_name(&ast, bindings[0]), b"a");
    }

    #[test]
    fn attr_path_merging_uses_static_string_names() {
        let ast = parse("{ \"a\".b = 1; a.c = 2; }");
        let NodeData::Children(bindings) = node(&ast, ast.root).data else {
            panic!("attrset children expected");
        };
        let bindings = child_ids(&ast, bindings);
        assert_eq!(bindings.len(), 1);
        assert_eq!(binding_name(&ast, bindings[0]), b"a");
    }

    #[test]
    fn dynamic_first_attr_paths_are_not_statically_merged() {
        let ast = parse("{ ${name}.b = 1; a.c = 2; }");
        let NodeData::Children(bindings) = node(&ast, ast.root).data else {
            panic!("attrset children expected");
        };
        let bindings = child_ids(&ast, bindings);
        assert_eq!(bindings.len(), 2);
    }

    #[test]
    fn duplicate_static_attr_paths_are_parse_errors() {
        for source in [
            "{ a.b = 1; a.b = 2; }",
            "{ a = 1; a.b = 2; }",
            "let x = 1; in { inherit x; x = 2; }",
            "let x = 1; in { inherit x; inherit x; }",
            "let x = 1; in { a = { inherit x; }; a.x = 2; }",
        ] {
            let error = parse_str(source).expect_err("duplicate attr path errors");
            assert_eq!(error.kind(), &ParseErrorKind::DuplicateAttribute);
        }
    }

    #[test]
    fn attr_path_merging_preserves_first_attrset_recursiveness() {
        let ast = parse("{ a = rec { c = c; }; a.b = 1; }");
        let NodeData::Children(bindings) = node(&ast, ast.root).data else {
            panic!("attrset children expected");
        };
        let (_, value) = binding_path_and_value(&ast, child_ids(&ast, bindings)[0]);
        assert_eq!(node(&ast, value).kind, NodeKind::RecAttrSet);

        let ast = parse("{ a.b = 1; a = rec { c = c; }; }");
        let NodeData::Children(bindings) = node(&ast, ast.root).data else {
            panic!("attrset children expected");
        };
        let (_, value) = binding_path_and_value(&ast, child_ids(&ast, bindings)[0]);
        assert_eq!(node(&ast, value).kind, NodeKind::AttrSet);
    }

    #[test]
    fn list_elements_do_not_consume_application_chains() {
        let ast = parse("[ 1 2 3 ]");
        let root = node(&ast, ast.root);
        let NodeData::Children(elements) = root.data else {
            panic!("list children expected");
        };
        assert_eq!(ast.arena.child_slice(elements).expect("elements").len(), 3);

        let ast = parse("[ f 1 2 ]");
        let root = node(&ast, ast.root);
        let NodeData::Children(elements) = root.data else {
            panic!("list children expected");
        };
        assert_eq!(ast.arena.child_slice(elements).expect("elements").len(), 3);

        let ast = parse("[ (f 1) 2 ]");
        let root = node(&ast, ast.root);
        let NodeData::Children(elements) = root.data else {
            panic!("list children expected");
        };
        let elements = ast.arena.child_slice(elements).expect("elements");
        assert_eq!(elements.len(), 2);
        assert_eq!(node(&ast, elements[0]).kind, NodeKind::Apply);
    }

    #[test]
    fn rejects_unparenthesized_full_expressions_in_lists() {
        for source in [
            "[ 1 + 2 ]",
            "[ f ? a ]",
            "[ ! f ]",
            "[ x: x ]",
            "[ if true then 1 else 2 ]",
        ] {
            parse_str(source).expect_err("list expression must be parenthesized");
        }

        let ast = parse("[ (1 + 2) ]");
        let root = node(&ast, ast.root);
        let NodeData::Children(elements) = root.data else {
            panic!("list children expected");
        };
        let elements = ast.arena.child_slice(elements).expect("elements");
        assert_eq!(elements.len(), 1);
        assert_eq!(node(&ast, elements[0]).kind, NodeKind::BinOp);
    }

    #[test]
    fn rejects_standalone_dynamic_interpolation() {
        let error = parse_str("${1}").expect_err("standalone interpolation is invalid");
        assert!(matches!(
            error.kind(),
            ParseErrorKind::UnexpectedToken {
                found: TokenKind::DollarBrace,
                ..
            }
        ));
    }

    #[test]
    fn rejects_pipe_operators_without_feature_gate() {
        parse_str("x |> f").expect_err("forward pipe is disabled");
        parse_str("f <| x").expect_err("reverse pipe is disabled");
    }

    #[test]
    fn parses_string_interpolation_fragments() {
        let ast = parse("\"a${x}b\"");
        let root = node(&ast, ast.root);
        assert_eq!(root.kind, NodeKind::Interp);
        let NodeData::Children(fragments) = root.data else {
            panic!("interpolation fragments expected");
        };
        assert_eq!(
            ast.arena.child_slice(fragments).expect("fragments").len(),
            3
        );
    }

    #[test]
    fn double_quoted_strings_decode_escape_forms() {
        let ast = parse("\"\\n\\r\\t\\\\\\\"\\${ $${\"");
        assert_eq!(string_bytes(&ast, ast.root), b"\n\r\t\\\"${ $${");

        let ast = parse("\"\\x\\ \\$\\a\"");
        assert_eq!(string_bytes(&ast, ast.root), b"x $a");
    }

    #[test]
    fn double_quoted_strings_preserve_raw_bytes() {
        let ast = parse_bytes(b"\"raw-\xff-byte\"").expect("string bytes parse");
        assert_eq!(string_bytes(&ast, ast.root), b"raw-\xff-byte");
    }

    #[test]
    fn double_quoted_strings_handle_dollar_runs_like_pinned_nix() {
        let ast = parse("\"$${\"");
        assert_eq!(string_bytes(&ast, ast.root), b"$${");

        let ast = parse("\"$$${x}\"");
        let root = node(&ast, ast.root);
        assert_eq!(root.kind, NodeKind::Interp);
        let NodeData::Children(fragments) = root.data else {
            panic!("interpolation fragments expected");
        };
        let fragments = child_ids(&ast, fragments);
        assert_eq!(fragments.len(), 2);
        assert_eq!(string_bytes(&ast, fragments[0]), b"$$");
        let interpolation = node(&ast, fragments[1]);
        assert_eq!(interpolation.kind, NodeKind::Interp);
        let NodeData::Node(expr) = interpolation.data else {
            panic!("interpolation expression expected");
        };
        assert_eq!(node(&ast, expr).kind, NodeKind::Ident);
        assert_eq!(string_bytes(&ast, expr), b"x");

        let ast = parse("\"$$$${\"");
        assert_eq!(string_bytes(&ast, ast.root), b"$$$${");

        parse_str("\"$$${\"").expect_err("third dollar opens an unterminated interpolation");
    }

    #[test]
    fn double_quoted_strings_normalize_literal_crlf() {
        let ast = parse("\"a\nb\"");
        assert_eq!(string_bytes(&ast, ast.root), b"a\nb");

        let ast = parse("\"a\rb\r\nc\"");
        assert_eq!(string_bytes(&ast, ast.root), b"a\nb\nc");
    }

    #[test]
    fn indented_strings_strip_common_spaces_and_opening_newline() {
        let ast = parse("''\n  one\n    two\n  ''");
        assert_eq!(string_bytes(&ast, ast.root), b"one\n  two\n");
    }

    #[test]
    fn indented_strings_ignore_empty_lines_and_keep_tabs() {
        let ast = parse("''\n  one\n\n  \tmake\n  ''");
        assert_eq!(string_bytes(&ast, ast.root), b"one\n\n\tmake\n");
    }

    #[test]
    fn indented_strings_decode_escape_forms() {
        let ast = parse("''''$ ''' ''\\n ''\\r ''\\t ''\\x ''${ $${''");
        assert_eq!(string_bytes(&ast, ast.root), b"$ '' \n \r \t x ${ $${");

        let ast = parse("''$$$${''");
        assert_eq!(string_bytes(&ast, ast.root), b"$$$${");
        parse_str("''$$${''").expect_err("odd dollar run opens interpolation");
    }

    #[test]
    fn indented_strings_treat_escaped_newline_as_indent_content() {
        let ast = parse("''\n  ''\\n\n    text\n  ''");
        assert_eq!(string_bytes(&ast, ast.root), b"\n\n  text\n");
    }

    #[test]
    fn indented_string_interpolation_at_line_start_counts_as_content() {
        let ast = parse("''\n  ${x}\n  text\n''");
        let root = node(&ast, ast.root);
        let NodeData::Children(fragments) = root.data else {
            panic!("interpolation fragments expected");
        };
        let fragments = ast.arena.child_slice(fragments).expect("fragments");
        assert_eq!(fragments.len(), 2);
        assert_eq!(node(&ast, fragments[0]).kind, NodeKind::Interp);
        assert_eq!(string_bytes(&ast, fragments[1]), b"\ntext\n");
    }

    #[test]
    fn parses_dynamic_attr_path_segments() {
        let ast = parse("pkg.${name}");
        let root = node(&ast, ast.root);
        assert_eq!(root.kind, NodeKind::Select);
        let NodeData::Select { path, .. } = root.data else {
            panic!("select data expected");
        };
        let path = ast.arena.child_slice(path).expect("path");
        assert_eq!(path.len(), 1);
        assert_eq!(node(&ast, path[0]).kind, NodeKind::Interp);
    }
}
