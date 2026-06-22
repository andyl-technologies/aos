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

mod atoms;
mod attrs;
mod expr;
mod lambda;
mod strings;

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
    /// A path literal ended with a bare slash.
    #[error("path has a trailing slash")]
    PathTrailingSlash,
    /// Two bindings define the same non-mergeable attribute.
    #[error("attribute already defined")]
    DuplicateAttribute {
        /// The earlier binding for this attribute.
        first: Span,
        /// The conflicting later binding for this attribute.
        second: Span,
    },
    /// A formal argument pattern violates Nix's shape restrictions.
    #[error("invalid formal argument pattern: {reason}")]
    InvalidFormalPattern {
        /// The violated formal-pattern rule.
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests;
