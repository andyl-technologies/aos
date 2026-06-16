//! Byte-oriented lexer for Nix source.
//!
//! The lexer is a single-pass scanner over source bytes. It owns no token text:
//! every token is a [`TokenKind`] plus a byte [`Span`], and callers recover the
//! corresponding source slice only when they need to intern or diagnose it.
//! Trivia is retained so tooling can reconstruct source, while parser code can
//! skip trivia with a single token-kind check.

use std::convert::TryFrom;

use thiserror::Error;

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

    fn lex_token(&mut self) -> Result<Token, LexError> {
        loop {
            return match self.current_mode() {
                Mode::Normal | Mode::Interpolation { .. } => self.lex_normal(),
                Mode::Path => {
                    if self.path_fragment_is_done() {
                        self.modes.pop();
                        continue;
                    }
                    self.lex_path_fragment()
                }
                Mode::DoubleString => self.lex_double_string(),
                Mode::IndentedString => self.lex_indented_string(),
            };
        }
    }

    fn lex_normal(&mut self) -> Result<Token, LexError> {
        let start = self.cursor;

        if self.is_eof() {
            return match self.current_mode() {
                Mode::Interpolation { .. } => {
                    Err(self.error_at(start, LexErrorKind::UnterminatedInterpolation))
                }
                _ => self.token(TokenKind::Eof, start, start),
            };
        }

        let byte = self.source[self.cursor];

        if is_whitespace(byte) {
            self.cursor += 1;
            while self.peek_byte().is_some_and(is_whitespace) {
                self.cursor += 1;
            }
            return self.token(TokenKind::Whitespace, start, self.cursor);
        }

        if byte == b'#' {
            self.cursor += 1;
            while let Some(next) = self.peek_byte() {
                if next == b'\n' {
                    break;
                }
                self.cursor += 1;
            }
            return self.token(TokenKind::LineComment, start, self.cursor);
        }

        if self.starts_with(b"/*") {
            return self.lex_block_comment(start);
        }

        if byte == b'"' {
            self.cursor += 1;
            self.modes.push(Mode::DoubleString);
            return self.token(TokenKind::StrStart, start, self.cursor);
        }

        if self.starts_with(b"''") {
            self.cursor += 2;
            self.modes.push(Mode::IndentedString);
            return self.token(TokenKind::IndStrStart, start, self.cursor);
        }

        if self.path_starts_here() {
            return self.lex_path(start);
        }

        if self.uri_starts_here() {
            return self.lex_uri(start);
        }

        if byte.is_ascii_digit()
            || (byte == b'.' && self.peek_offset(1).is_some_and(|b| b.is_ascii_digit()))
        {
            return self.lex_number(start);
        }

        if is_ident_start(byte) {
            return self.lex_ident_or_keyword(start);
        }

        self.lex_punctuation(start)
    }

    fn lex_block_comment(&mut self, start: usize) -> Result<Token, LexError> {
        self.cursor += 2;

        while !self.is_eof() {
            if self.starts_with(b"*/") {
                self.cursor += 2;
                return self.token(TokenKind::BlockComment, start, self.cursor);
            }
            self.cursor += 1;
        }

        Err(self.error_at(start, LexErrorKind::UnterminatedBlockComment))
    }

    fn lex_number(&mut self, start: usize) -> Result<Token, LexError> {
        let mut kind = TokenKind::Int;

        if self.peek_byte() == Some(b'.') {
            kind = TokenKind::Float;
            self.cursor += 1;
            while self.peek_byte().is_some_and(|b| b.is_ascii_digit()) {
                self.cursor += 1;
            }
        } else {
            while self.peek_byte().is_some_and(|b| b.is_ascii_digit()) {
                self.cursor += 1;
            }

            if self.peek_byte() == Some(b'.') && self.peek_offset(1) != Some(b'.') {
                kind = TokenKind::Float;
                self.cursor += 1;
                while self.peek_byte().is_some_and(|b| b.is_ascii_digit()) {
                    self.cursor += 1;
                }
            }
        }

        if kind == TokenKind::Float && matches!(self.peek_byte(), Some(b'e' | b'E')) {
            let exponent_start = self.cursor;
            self.cursor += 1;
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.cursor += 1;
            }

            if self.peek_byte().is_some_and(|b| b.is_ascii_digit()) {
                while self.peek_byte().is_some_and(|b| b.is_ascii_digit()) {
                    self.cursor += 1;
                }
            } else {
                self.cursor = exponent_start;
            }
        }

        self.token(kind, start, self.cursor)
    }

    fn lex_ident_or_keyword(&mut self, start: usize) -> Result<Token, LexError> {
        self.cursor += 1;
        while self.peek_byte().is_some_and(is_ident_continue) {
            self.cursor += 1;
        }

        let kind = match &self.source[start..self.cursor] {
            b"let" => TokenKind::Let,
            b"in" => TokenKind::In,
            b"if" => TokenKind::If,
            b"then" => TokenKind::Then,
            b"else" => TokenKind::Else,
            b"with" => TokenKind::With,
            b"rec" => TokenKind::Rec,
            b"inherit" => TokenKind::Inherit,
            b"assert" => TokenKind::Assert,
            b"or" => TokenKind::Or,
            _ => TokenKind::Ident,
        };

        self.token(kind, start, self.cursor)
    }

    fn lex_path(&mut self, start: usize) -> Result<Token, LexError> {
        self.lex_path_tail(start)
    }

    fn lex_path_tail(&mut self, start: usize) -> Result<Token, LexError> {
        while let Some(byte) = self.peek_byte() {
            if self.starts_with(b"${") {
                self.modes.push(Mode::Path);
                break;
            }

            if byte == b'/' && matches!(self.peek_offset(1), Some(b'/') | Some(b'*')) {
                break;
            }

            if self.cursor == start && byte == b'~' && self.peek_offset(1) == Some(b'/') {
                self.cursor += 1;
                continue;
            }

            if byte == b'/' || is_path_char(byte) {
                self.cursor += 1;
                continue;
            }

            break;
        }

        self.token(TokenKind::Path, start, self.cursor)
    }

    fn lex_path_fragment(&mut self) -> Result<Token, LexError> {
        let start = self.cursor;

        if self.starts_with(b"${") {
            self.cursor += 2;
            self.modes.push(Mode::Interpolation { brace_depth: 0 });
            return self.token(TokenKind::DollarBrace, start, self.cursor);
        }

        self.lex_path_tail(start)
    }

    fn lex_uri(&mut self, start: usize) -> Result<Token, LexError> {
        self.cursor += 1;
        while self.peek_byte().is_some_and(is_uri_scheme_continue) {
            self.cursor += 1;
        }

        self.cursor += 1;
        while self.peek_byte().is_some_and(is_uri_body) {
            self.cursor += 1;
        }

        self.token(TokenKind::Uri, start, self.cursor)
    }

    fn lex_punctuation(&mut self, start: usize) -> Result<Token, LexError> {
        let byte = self.source[self.cursor];

        let kind = match byte {
            b'=' if self.peek_offset(1) == Some(b'=') => {
                self.cursor += 2;
                TokenKind::EqEq
            }
            b'=' => {
                self.cursor += 1;
                TokenKind::Assign
            }
            b';' => {
                self.cursor += 1;
                TokenKind::Semi
            }
            b':' => {
                self.cursor += 1;
                TokenKind::Colon
            }
            b',' => {
                self.cursor += 1;
                TokenKind::Comma
            }
            b'.' if self.starts_with(b"...") => {
                self.cursor += 3;
                TokenKind::Ellipsis
            }
            b'.' => {
                self.cursor += 1;
                TokenKind::Dot
            }
            b'@' => {
                self.cursor += 1;
                TokenKind::At
            }
            b'?' => {
                self.cursor += 1;
                TokenKind::Question
            }
            b'(' => {
                self.cursor += 1;
                TokenKind::LParen
            }
            b')' => {
                self.cursor += 1;
                TokenKind::RParen
            }
            b'{' => {
                self.cursor += 1;
                self.increment_interpolation_depth();
                TokenKind::LBrace
            }
            b'}' => {
                self.cursor += 1;
                if self.close_interpolation_if_ready() {
                    return self.token(TokenKind::RBrace, start, self.cursor);
                }
                TokenKind::RBrace
            }
            b'[' => {
                self.cursor += 1;
                TokenKind::LBracket
            }
            b']' => {
                self.cursor += 1;
                TokenKind::RBracket
            }
            b'+' if self.peek_offset(1) == Some(b'+') => {
                self.cursor += 2;
                TokenKind::Concat
            }
            b'+' => {
                self.cursor += 1;
                TokenKind::Plus
            }
            b'-' if self.peek_offset(1) == Some(b'>') => {
                self.cursor += 2;
                TokenKind::Impl
            }
            b'-' => {
                self.cursor += 1;
                TokenKind::Minus
            }
            b'*' => {
                self.cursor += 1;
                TokenKind::Star
            }
            b'/' if self.peek_offset(1) == Some(b'/') => {
                self.cursor += 2;
                TokenKind::Update
            }
            b'/' => {
                self.cursor += 1;
                TokenKind::Slash
            }
            b'<' if self.peek_offset(1) == Some(b'=') => {
                self.cursor += 2;
                TokenKind::LessEq
            }
            b'<' if self.peek_offset(1) == Some(b'|') => {
                self.cursor += 2;
                TokenKind::PipeLeft
            }
            b'<' if self.search_path_starts_here() => return self.lex_search_path(start),
            b'<' => {
                self.cursor += 1;
                TokenKind::Less
            }
            b'>' if self.peek_offset(1) == Some(b'=') => {
                self.cursor += 2;
                TokenKind::GreaterEq
            }
            b'>' => {
                self.cursor += 1;
                TokenKind::Greater
            }
            b'!' if self.peek_offset(1) == Some(b'=') => {
                self.cursor += 2;
                TokenKind::NotEq
            }
            b'!' => {
                self.cursor += 1;
                TokenKind::Not
            }
            b'&' if self.peek_offset(1) == Some(b'&') => {
                self.cursor += 2;
                TokenKind::And
            }
            b'|' if self.peek_offset(1) == Some(b'|') => {
                self.cursor += 2;
                TokenKind::OrOr
            }
            b'|' if self.peek_offset(1) == Some(b'>') => {
                self.cursor += 2;
                TokenKind::PipeRight
            }
            _ => return Err(self.error_at(start, LexErrorKind::UnexpectedByte(byte))),
        };

        self.token(kind, start, self.cursor)
    }

    fn lex_search_path(&mut self, start: usize) -> Result<Token, LexError> {
        self.cursor += 1;
        let mut last_was_slash = false;

        while let Some(byte) = self.peek_byte() {
            if byte == b'>' {
                if last_was_slash {
                    return Err(self.error_at(self.cursor, LexErrorKind::UnexpectedByte(byte)));
                }
                self.cursor += 1;
                return self.token(TokenKind::SPath, start, self.cursor);
            }

            if is_whitespace(byte) {
                return Err(self.error_at(start, LexErrorKind::UnterminatedSearchPath));
            }

            if byte == b'/' {
                if last_was_slash {
                    return Err(self.error_at(self.cursor, LexErrorKind::UnexpectedByte(byte)));
                }
                last_was_slash = true;
                self.cursor += 1;
                continue;
            }

            if !is_search_path_segment_byte(byte) {
                return Err(self.error_at(self.cursor, LexErrorKind::UnexpectedByte(byte)));
            }

            last_was_slash = false;
            self.cursor += 1;
        }

        Err(self.error_at(start, LexErrorKind::UnterminatedSearchPath))
    }

    fn lex_double_string(&mut self) -> Result<Token, LexError> {
        let start = self.cursor;

        if self.is_eof() {
            return Err(self.error_at(start, LexErrorKind::UnterminatedString));
        }

        if self.peek_byte() == Some(b'"') {
            self.cursor += 1;
            self.pop_string_mode();
            return self.token(TokenKind::StrEnd, start, self.cursor);
        }

        if self.starts_with(b"${") {
            self.cursor += 2;
            self.modes.push(Mode::Interpolation { brace_depth: 0 });
            return self.token(TokenKind::DollarBrace, start, self.cursor);
        }

        while let Some(byte) = self.peek_byte() {
            if byte == b'"' || self.starts_with(b"${") {
                break;
            }

            if self.starts_with(b"$${") {
                self.cursor += 3;
                continue;
            }

            if byte == b'\\' {
                self.cursor += 1;
                if !self.is_eof() {
                    self.cursor += 1;
                }
                continue;
            }

            self.cursor += 1;
        }

        self.token(TokenKind::StrPart, start, self.cursor)
    }

    fn lex_indented_string(&mut self) -> Result<Token, LexError> {
        let start = self.cursor;

        if self.is_eof() {
            return Err(self.error_at(start, LexErrorKind::UnterminatedString));
        }

        if self.indented_string_closes_here() {
            self.cursor += 2;
            self.pop_string_mode();
            return self.token(TokenKind::IndStrEnd, start, self.cursor);
        }

        if self.starts_with(b"${") {
            self.cursor += 2;
            self.modes.push(Mode::Interpolation { brace_depth: 0 });
            return self.token(TokenKind::DollarBrace, start, self.cursor);
        }

        while !self.is_eof() {
            if self.indented_string_closes_here() || self.starts_with(b"${") {
                break;
            }

            if self.starts_with(b"$${") {
                self.cursor += 3;
                continue;
            }

            if self.starts_with(b"''") {
                self.cursor += 2;
                if !self.is_eof() {
                    self.cursor += 1;
                }
                continue;
            }

            self.cursor += 1;
        }

        self.token(TokenKind::IndStrPart, start, self.cursor)
    }

    fn current_mode(&self) -> Mode {
        self.modes.last().copied().unwrap_or(Mode::Normal)
    }

    fn pop_string_mode(&mut self) {
        if matches!(
            self.current_mode(),
            Mode::DoubleString | Mode::IndentedString
        ) {
            self.modes.pop();
        }
    }

    fn increment_interpolation_depth(&mut self) {
        if let Some(Mode::Interpolation { brace_depth }) = self.modes.last_mut() {
            *brace_depth = brace_depth.saturating_add(1);
        }
    }

    fn close_interpolation_if_ready(&mut self) -> bool {
        let Some(Mode::Interpolation { brace_depth }) = self.modes.last_mut() else {
            return false;
        };

        if *brace_depth == 0 {
            self.modes.pop();
            true
        } else {
            *brace_depth -= 1;
            false
        }
    }

    fn indented_string_closes_here(&self) -> bool {
        self.starts_with(b"''") && !matches!(self.peek_offset(2), Some(b'\'' | b'$' | b'\\'))
    }

    fn path_fragment_is_done(&self) -> bool {
        self.is_eof()
            || (!self.starts_with(b"${") && !self.path_continues_here())
            || matches!(
                (self.peek_byte(), self.peek_offset(1)),
                (Some(b'/'), Some(b'/' | b'*'))
            )
    }

    fn path_starts_here(&self) -> bool {
        if self.starts_with(b"~/") {
            return true;
        }

        let mut cursor = self.cursor;
        let mut saw_slash = false;

        while let Some(byte) = self.source.get(cursor).copied() {
            if self.source[cursor..].starts_with(b"${") {
                return saw_slash;
            }

            if byte == b'/' {
                if matches!(self.source.get(cursor + 1), Some(b'/' | b'*')) {
                    return saw_slash;
                }
                if cursor == self.cursor && !self.path_segment_starts_after_slash(cursor) {
                    return false;
                }
                saw_slash = true;
                cursor += 1;
                continue;
            }

            if is_path_char(byte) {
                cursor += 1;
                continue;
            }

            break;
        }

        saw_slash
    }

    fn path_continues_here(&self) -> bool {
        matches!(self.peek_byte(), Some(b'/')) || self.peek_byte().is_some_and(is_path_char)
    }

    fn path_segment_starts_after_slash(&self, slash: usize) -> bool {
        self.source
            .get(slash + 1)
            .copied()
            .is_some_and(is_path_char)
            || self.source[slash + 1..].starts_with(b"${")
    }

    fn search_path_starts_here(&self) -> bool {
        self.peek_byte() == Some(b'<')
            && self.peek_offset(1).is_some_and(is_search_path_segment_byte)
    }

    fn uri_starts_here(&self) -> bool {
        if !self
            .peek_byte()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        {
            return false;
        }

        let mut cursor = self.cursor + 1;
        while self
            .source
            .get(cursor)
            .copied()
            .is_some_and(is_uri_scheme_continue)
        {
            cursor += 1;
        }

        self.source.get(cursor) == Some(&b':')
            && self
                .source
                .get(cursor + 1)
                .copied()
                .is_some_and(is_uri_body)
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

impl Iterator for Lexer<'_> {
    type Item = Result<Token, LexError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.iterator_finished {
            return None;
        }

        let token = self.next_token();
        if matches!(
            token,
            Ok(Token {
                kind: TokenKind::Eof,
                ..
            }) | Err(_)
        ) {
            self.iterator_finished = true;
        }
        Some(token)
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
                | b'#'
        )
}

fn is_path_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
}

fn is_search_path_segment_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'+')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex_kinds(source: &str) -> Result<Vec<TokenKind>, LexError> {
        Lexer::from_source_str(source)
            .map(|result| result.map(|token| token.kind))
            .collect()
    }

    fn lex_tokens(source: &str) -> Result<Vec<Token>, LexError> {
        Lexer::from_source_str(source).collect()
    }

    #[test]
    fn token_kind_is_one_byte_and_token_is_copy_sized() {
        assert_eq!(std::mem::size_of::<TokenKind>(), 1);
        assert_eq!(std::mem::size_of::<Span>(), 8);
        assert!(std::mem::size_of::<Token>() <= 12);
    }

    #[test]
    fn emits_keywords_identifiers_and_trivia() {
        let kinds = lex_kinds("let x' = 1; # hi\nin x'").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Let,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Assign,
                TokenKind::Whitespace,
                TokenKind::Int,
                TokenKind::Semi,
                TokenKind::Whitespace,
                TokenKind::LineComment,
                TokenKind::Whitespace,
                TokenKind::In,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn keeps_source_slices_by_span() {
        let mut lexer = Lexer::from_source_str("abc 123");
        let ident = lexer.next_token().expect("identifier token");
        let trivia = lexer.next_token().expect("trivia token");
        let int = lexer.next_token().expect("integer token");

        assert_eq!(lexer.slice(ident).expect("valid ident span"), b"abc");
        assert_eq!(lexer.slice(trivia).expect("valid trivia span"), b" ");
        assert_eq!(lexer.slice(int).expect("valid integer span"), b"123");
    }

    #[test]
    fn supports_one_token_lookahead() {
        let mut lexer = Lexer::from_source_str("let");
        let peeked = lexer.peek().expect("peek token");
        let next = lexer.next_token().expect("next token");
        assert_eq!(peeked, next);
        assert_eq!(next.kind, TokenKind::Let);
    }

    #[test]
    fn classifies_local_nix_number_boundaries() {
        let kinds = lex_kinds("1 1. .5 1e10 1.5e-3").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Int,
                TokenKind::Whitespace,
                TokenKind::Float,
                TokenKind::Whitespace,
                TokenKind::Float,
                TokenKind::Whitespace,
                TokenKind::Int,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Float,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn distinguishes_paths_division_update_and_uris() {
        let kinds =
            lex_kinds("a/b a /b a / b ./x ../y /abs ~/z a // b https://x/y").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Slash,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Update,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Uri,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn accepts_cxx_nix_path_prefix_boundaries() {
        let kinds = lex_kinds("foo.bar/baz foo+bar/baz 1/foo 1.5/foo foo/bar/").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Path,
                TokenKind::Whitespace,
                TokenKind::Path,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn rejects_or_splits_invalid_path_body_bytes() {
        assert_eq!(
            lex_kinds("foo$bar/baz")
                .expect_err("dollar is not a path body byte")
                .kind(),
            &LexErrorKind::UnexpectedByte(b'$')
        );
        assert_eq!(
            lex_kinds("foo%bar/baz")
                .expect_err("percent is not a path body byte")
                .kind(),
            &LexErrorKind::UnexpectedByte(b'%')
        );

        let kinds = lex_kinds("foo*bar/baz").expect("star splits the expression");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Ident,
                TokenKind::Star,
                TokenKind::Path,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn accepts_and_rejects_uri_scheme_boundaries() {
        let kinds = lex_kinds("git+ssh://example/path foo.bar:baz foo-bar:baz").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Uri,
                TokenKind::Whitespace,
                TokenKind::Uri,
                TokenKind::Whitespace,
                TokenKind::Uri,
                TokenKind::Eof,
            ]
        );

        let kinds = lex_kinds("foo_bar:baz foo'bar:baz").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Ident,
                TokenKind::Colon,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Colon,
                TokenKind::Ident,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn splits_path_interpolation_into_expression_tokens() {
        let kinds = lex_kinds("./a/${x}/b").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Path,
                TokenKind::DollarBrace,
                TokenKind::Ident,
                TokenKind::RBrace,
                TokenKind::Path,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn distinguishes_search_paths_from_comparison() {
        let kinds = lex_kinds("<nixpkgs/lib> a < b <= c <| d").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::SPath,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Less,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::LessEq,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::PipeLeft,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn validates_search_path_segments() {
        let kinds = lex_kinds("<a/b/c>").expect("multi-segment search path lexes");
        assert_eq!(kinds, vec![TokenKind::SPath, TokenKind::Eof]);

        let leading_slash = lex_kinds("</foo>").expect("leading slash is not an SPath token");
        assert_eq!(
            leading_slash,
            vec![
                TokenKind::Less,
                TokenKind::Path,
                TokenKind::Greater,
                TokenKind::Eof,
            ]
        );

        assert_eq!(
            lex_kinds("<foo/>")
                .expect_err("trailing slash is invalid in search path")
                .kind(),
            &LexErrorKind::UnexpectedByte(b'>')
        );
        assert_eq!(
            lex_kinds("<foo//bar>")
                .expect_err("empty search path segment is invalid")
                .kind(),
            &LexErrorKind::UnexpectedByte(b'/')
        );
    }

    #[test]
    fn rejects_invalid_search_path_body_bytes() {
        assert_eq!(
            lex_kinds("<foo$bar>")
                .expect_err("dollar is invalid in search path")
                .kind(),
            &LexErrorKind::UnexpectedByte(b'$')
        );
        assert_eq!(
            lex_kinds("<foo:bar>")
                .expect_err("colon is invalid in search path")
                .kind(),
            &LexErrorKind::UnexpectedByte(b':')
        );
    }

    #[test]
    fn emits_double_quoted_string_fragments_and_interpolation() {
        let kinds = lex_kinds("\"a${x}b\"").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::StrStart,
                TokenKind::StrPart,
                TokenKind::DollarBrace,
                TokenKind::Ident,
                TokenKind::RBrace,
                TokenKind::StrPart,
                TokenKind::StrEnd,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn keeps_escaped_double_string_interpolation_as_text() {
        let tokens = lex_tokens("\"\\${x} $${y}\"").expect("lexes");
        let parts: Vec<&[u8]> = tokens
            .iter()
            .filter(|token| token.kind == TokenKind::StrPart)
            .map(|token| {
                Lexer::from_source_str("\"\\${x} $${y}\"")
                    .slice(*token)
                    .expect("valid string span")
            })
            .collect();

        assert_eq!(parts, vec![b"\\${x} $${y}".as_slice()]);
    }

    #[test]
    fn tracks_nested_interpolation_braces() {
        let kinds = lex_kinds("\"${{ a = \"b\"; }}\"").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::StrStart,
                TokenKind::DollarBrace,
                TokenKind::LBrace,
                TokenKind::Whitespace,
                TokenKind::Ident,
                TokenKind::Whitespace,
                TokenKind::Assign,
                TokenKind::Whitespace,
                TokenKind::StrStart,
                TokenKind::StrPart,
                TokenKind::StrEnd,
                TokenKind::Semi,
                TokenKind::Whitespace,
                TokenKind::RBrace,
                TokenKind::RBrace,
                TokenKind::StrEnd,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn emits_indented_string_fragments_and_interpolation() {
        let kinds = lex_kinds("''a${x}b''").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::IndStrStart,
                TokenKind::IndStrPart,
                TokenKind::DollarBrace,
                TokenKind::Ident,
                TokenKind::RBrace,
                TokenKind::IndStrPart,
                TokenKind::IndStrEnd,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn indented_string_escape_prefix_does_not_close() {
        let kinds = lex_kinds("'''''''").expect("lexes");
        assert_eq!(
            kinds,
            vec![
                TokenKind::IndStrStart,
                TokenKind::IndStrPart,
                TokenKind::IndStrEnd,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn reports_unterminated_constructs() {
        assert_eq!(
            Lexer::from_source_str("/* nope")
                .next_token()
                .expect_err("unterminated block comment")
                .kind(),
            &LexErrorKind::UnterminatedBlockComment
        );
        assert_eq!(
            Lexer::from_source_str("\"nope")
                .nth(2)
                .expect("unterminated string result")
                .expect_err("unterminated string")
                .kind(),
            &LexErrorKind::UnterminatedString
        );
        assert_eq!(
            Lexer::from_source_str("\"${x")
                .last()
                .expect("last token")
                .expect_err("unterminated interpolation")
                .kind(),
            &LexErrorKind::UnterminatedInterpolation
        );
    }
}
