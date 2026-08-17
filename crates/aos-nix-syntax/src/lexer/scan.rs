//! Core token scanning: the normal-mode dispatch, literals, identifiers,
//! paths, URIs, punctuation, search paths, and the [`Iterator`] driver.

use super::*;

impl<'a> Lexer<'a> {
    pub(super) fn lex_token(&mut self) -> Result<Token, LexError> {
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
                if matches!(next, b'\n' | b'\r') {
                    break;
                }
                self.cursor += 1;
            }
            return self.token(TokenKind::LineComment, start, self.cursor);
        }

        if self.starts_with(b"/*") {
            return self.lex_block_comment(start);
        }

        if self.starts_with(b"${") {
            self.cursor += 2;
            self.modes.push(Mode::Interpolation { brace_depth: 0 });
            return self.token(TokenKind::DollarBrace, start, self.cursor);
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
            return self.path_segment_starts_after_slash(self.cursor + 1);
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
                saw_slash |= self.path_segment_starts_after_slash(cursor);
                cursor += 1;
                continue;
            }

            if is_path_char(byte) {
                cursor += 1;
                continue;
            }

            break;
        }

        if matches!(&self.source[self.cursor..cursor], b"./" | b"../") {
            return false;
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
