//! Double-quoted and indented string lexing, plus the interpolation
//! brace-depth and dollar-escape bookkeeping those modes rely on.

use super::*;

impl Lexer<'_> {
    pub(super) fn lex_double_string(&mut self) -> Result<Token, LexError> {
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

            if byte == b'$' {
                if !self.consume_string_dollar_run() {
                    break;
                }
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

    pub(super) fn lex_indented_string(&mut self) -> Result<Token, LexError> {
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

            if self.peek_byte() == Some(b'$') {
                if !self.consume_string_dollar_run() {
                    break;
                }
                continue;
            }

            if self.starts_with(b"''\\") {
                self.cursor += 3;
                if !self.is_eof() {
                    self.cursor += 1;
                }
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

    fn pop_string_mode(&mut self) {
        if matches!(
            self.current_mode(),
            Mode::DoubleString | Mode::IndentedString
        ) {
            self.modes.pop();
        }
    }

    pub(super) fn increment_interpolation_depth(&mut self) {
        if let Some(Mode::Interpolation { brace_depth }) = self.modes.last_mut() {
            *brace_depth = brace_depth.saturating_add(1);
        }
    }

    pub(super) fn close_interpolation_if_ready(&mut self) -> bool {
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

    fn consume_string_dollar_run(&mut self) -> bool {
        let start = self.cursor;
        while self.peek_byte() == Some(b'$') {
            self.cursor += 1;
        }
        let run = self.cursor - start;
        if self.peek_byte() != Some(b'{') {
            return true;
        }

        if run == 1 {
            self.cursor = start;
            return false;
        }

        if run.is_multiple_of(2) {
            self.cursor += 1;
        } else {
            self.cursor = start + run - 1;
        }
        true
    }
}
