//! Byte-oriented lexer for Nix source.
//!
//! The lexer is a single-pass scanner over source bytes. It owns no token text:
//! every token is a [`TokenKind`] plus a byte [`Span`], and callers recover the
//! corresponding source slice only when they need to intern or diagnose it.
//! Trivia is retained so tooling can reconstruct source, while parser code can
//! skip trivia with a single token-kind check.

use std::convert::TryFrom;

use thiserror::Error;

mod scan;
mod strings;

/// A byte span in a Nix source buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Span {
    /// Byte offset of the first byte in the span.
    pub start: u32,
    /// Byte offset one past the final byte in the span.
    pub end: u32,
}

impl Span {
    /// Creates a span from byte offsets.
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Returns the length of the span in bytes.
    pub const fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Returns whether this span covers no bytes.
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// A lexical token with no owned text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Token {
    /// The token's syntactic category.
    pub kind: TokenKind,
    /// The token's byte span in the original source.
    pub span: Span,
}

impl Token {
    /// Creates a token from a kind and span.
    pub const fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }
}

/// The one-byte token taxonomy emitted by the lexer.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// An integer literal.
    Int,
    /// A floating-point literal.
    Float,
    /// An identifier or unreserved name.
    Ident,
    /// A path literal.
    Path,
    /// A search-path literal such as `<nixpkgs>`.
    SPath,
    /// A URI literal.
    Uri,
    /// The opening quote of a double-quoted string.
    StrStart,
    /// A literal fragment in a double-quoted string.
    StrPart,
    /// The closing quote of a double-quoted string.
    StrEnd,
    /// The opening `''` of an indented string.
    IndStrStart,
    /// A literal fragment in an indented string.
    IndStrPart,
    /// The closing `''` of an indented string.
    IndStrEnd,
    /// The `${` marker that begins interpolation.
    DollarBrace,
    /// The `let` keyword.
    Let,
    /// The `in` keyword.
    In,
    /// The `if` keyword.
    If,
    /// The `then` keyword.
    Then,
    /// The `else` keyword.
    Else,
    /// The `with` keyword.
    With,
    /// The `rec` keyword.
    Rec,
    /// The `inherit` keyword.
    Inherit,
    /// The `assert` keyword.
    Assert,
    /// The contextual `or` keyword.
    Or,
    /// The `=` token.
    Assign,
    /// The `;` token.
    Semi,
    /// The `:` token.
    Colon,
    /// The `,` token.
    Comma,
    /// The `.` token.
    Dot,
    /// The `@` token.
    At,
    /// The `?` token.
    Question,
    /// The `(` token.
    LParen,
    /// The `)` token.
    RParen,
    /// The `{` token.
    LBrace,
    /// The `}` token.
    RBrace,
    /// The `[` token.
    LBracket,
    /// The `]` token.
    RBracket,
    /// The `...` token.
    Ellipsis,
    /// The `++` token.
    Concat,
    /// The `//` token.
    Update,
    /// The `->` implication token.
    Impl,
    /// The `+` token.
    Plus,
    /// The `-` token.
    Minus,
    /// The `*` token.
    Star,
    /// The `/` token.
    Slash,
    /// The `<` token.
    Less,
    /// The `>` token.
    Greater,
    /// The `<=` token.
    LessEq,
    /// The `>=` token.
    GreaterEq,
    /// The `==` token.
    EqEq,
    /// The `!=` token.
    NotEq,
    /// The `&&` token.
    And,
    /// The `||` token.
    OrOr,
    /// The `!` token.
    Not,
    /// The experimental `|>` token.
    PipeRight,
    /// The experimental `<|` token.
    PipeLeft,
    /// Whitespace outside strings.
    Whitespace,
    /// A `#` line comment.
    LineComment,
    /// A non-nesting `/* ... */` block comment.
    BlockComment,
    /// The terminal end-of-file token.
    Eof,
}

impl TokenKind {
    /// Returns whether this token is trivia.
    pub const fn is_trivia(self) -> bool {
        matches!(
            self,
            Self::Whitespace | Self::LineComment | Self::BlockComment
        )
    }
}

/// A lexer failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{kind} at byte span {span:?}")]
pub struct LexError {
    kind: LexErrorKind,
    span: Span,
}

impl LexError {
    /// Creates a lexer error at a span.
    pub const fn new(kind: LexErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Returns the error category.
    pub const fn kind(&self) -> &LexErrorKind {
        &self.kind
    }

    /// Returns the byte span associated with the error.
    pub const fn span(&self) -> Span {
        self.span
    }
}

/// The category of a lexer failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LexErrorKind {
    /// The scanner encountered a byte that cannot begin any token.
    #[error("unexpected byte 0x{0:02x}")]
    UnexpectedByte(u8),
    /// A `/*` block comment reached EOF before `*/`.
    #[error("unterminated block comment")]
    UnterminatedBlockComment,
    /// A double-quoted or indented string reached EOF before its terminator.
    #[error("unterminated string")]
    UnterminatedString,
    /// A `${` interpolation reached EOF before its closing `}`.
    #[error("unterminated interpolation")]
    UnterminatedInterpolation,
    /// A `<...>` search-path literal reached EOF or whitespace before `>`.
    #[error("unterminated search path")]
    UnterminatedSearchPath,
    /// The source is too large to represent spans as `u32` byte offsets.
    #[error("source offset exceeds u32 range")]
    OffsetOverflow,
}

/// A byte-oriented Nix lexer with one-token lookahead.
#[derive(Clone, Debug)]
pub struct Lexer<'a> {
    source: &'a [u8],
    cursor: usize,
    modes: Vec<Mode>,
    lookahead: Option<Result<Token, LexError>>,
    iterator_finished: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    Path,
    DoubleString,
    IndentedString,
    Interpolation { brace_depth: u32 },
}

impl<'a> Lexer<'a> {
    /// Creates a lexer over source bytes.
    pub fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            cursor: 0,
            modes: vec![Mode::Normal],
            lookahead: None,
            iterator_finished: false,
        }
    }

    /// Creates a lexer over a UTF-8 source string.
    pub fn from_source_str(source: &'a str) -> Self {
        Self::new(source.as_bytes())
    }

    /// Returns the source bytes scanned by this lexer.
    pub const fn source(&self) -> &'a [u8] {
        self.source
    }

    /// Returns the source slice covered by a token.
    pub fn slice(&self, token: Token) -> Option<&'a [u8]> {
        let start = token.span.start as usize;
        let end = token.span.end as usize;
        self.source.get(start..end)
    }

    /// Peeks at the next token without consuming it.
    ///
    /// # Errors
    ///
    /// Returns a [`LexError`] if the next byte sequence is not a valid token or
    /// if the current string/comment/interpolation mode is unterminated.
    pub fn peek(&mut self) -> Result<Token, LexError> {
        if self.lookahead.is_none() {
            let token = self.lex_token();
            self.lookahead = Some(token);
        }

        match &self.lookahead {
            Some(Ok(token)) => Ok(*token),
            Some(Err(error)) => Err(error.clone()),
            None => self.lex_token(),
        }
    }

    /// Consumes and returns the next token.
    ///
    /// # Errors
    ///
    /// Returns a [`LexError`] if the next byte sequence is not a valid token or
    /// if the current string/comment/interpolation mode is unterminated.
    pub fn next_token(&mut self) -> Result<Token, LexError> {
        if let Some(token) = self.lookahead.take() {
            return token;
        }

        self.lex_token()
    }

    fn current_mode(&self) -> Mode {
        self.modes.last().copied().unwrap_or(Mode::Normal)
    }

    fn starts_with(&self, needle: &[u8]) -> bool {
        self.source[self.cursor..].starts_with(needle)
    }

    fn peek_byte(&self) -> Option<u8> {
        self.source.get(self.cursor).copied()
    }

    fn peek_offset(&self, offset: usize) -> Option<u8> {
        self.source.get(self.cursor + offset).copied()
    }

    fn is_eof(&self) -> bool {
        self.cursor >= self.source.len()
    }

    fn token(&self, kind: TokenKind, start: usize, end: usize) -> Result<Token, LexError> {
        let span = self.span(start, end)?;
        Ok(Token::new(kind, span))
    }

    fn span(&self, start: usize, end: usize) -> Result<Span, LexError> {
        let start = u32::try_from(start).map_err(|_| {
            LexError::new(LexErrorKind::OffsetOverflow, Span::new(u32::MAX, u32::MAX))
        })?;
        let end = u32::try_from(end).map_err(|_| {
            LexError::new(LexErrorKind::OffsetOverflow, Span::new(u32::MAX, u32::MAX))
        })?;
        Ok(Span::new(start, end))
    }

    fn error_at(&self, offset: usize, kind: LexErrorKind) -> LexError {
        let offset = u32::try_from(offset).unwrap_or(u32::MAX);
        LexError::new(kind, Span::new(offset, offset))
    }
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'\'' | b'-')
}

fn is_uri_scheme_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

fn is_uri_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'%' | b'/'
                | b'?'
                | b':'
                | b'@'
                | b'&'
                | b'='
                | b'+'
                | b'$'
                | b','
                | b'_'
                | b'.'
                | b'!'
                | b'~'
                | b'*'
                | b'\''
                | b'-'
        )
}

fn is_path_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
}

fn is_search_path_segment_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'+')
}

#[cfg(test)]
mod tests;
