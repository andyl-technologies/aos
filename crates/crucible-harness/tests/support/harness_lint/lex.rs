//! Shared support for `lex`.

pub(super) fn tokenize(content: &str) -> Vec<Token> {
    let chars: Vec<char> = content.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;

    while index < chars.len() {
        let ch = chars[index];
        if ch == '\n' {
            line += 1;
            index += 1;
        } else if is_identifier_start(ch) {
            let start = index;
            index += 1;
            while index < chars.len() && is_identifier_continue(chars[index]) {
                index += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Ident(chars[start..index].iter().collect()),
                line,
            });
        } else {
            if matches!(
                ch,
                ':' | '!' | '<' | '>' | '{' | '}' | '(' | ')' | ',' | '.' | '=' | ';' | '&'
            ) {
                tokens.push(Token {
                    kind: TokenKind::Punct(ch),
                    line,
                });
            }
            index += 1;
        }
    }

    tokens
}

pub(super) fn previous_path_identifier(tokens: &[Token], index: usize) -> Option<&str> {
    match (
        tokens.get(index.checked_sub(3)?)?.kind.as_ident(),
        tokens.get(index - 2),
        tokens.get(index - 1),
    ) {
        (
            Some(identifier),
            Some(Token {
                kind: TokenKind::Punct(':'),
                ..
            }),
            Some(Token {
                kind: TokenKind::Punct(':'),
                ..
            }),
        ) => Some(identifier),
        _ => None,
    }
}

pub(super) fn previous_key_identifier(tokens: &[Token], index: usize) -> Option<&str> {
    match (
        tokens.get(index.checked_sub(2)?)?.kind.as_ident(),
        tokens.get(index - 1),
    ) {
        (
            Some(identifier),
            Some(Token {
                kind: TokenKind::Punct('='),
                ..
            }),
        ) => Some(identifier),
        _ => None,
    }
}

pub(super) fn previous_is_punct(tokens: &[Token], index: usize, punctuation: char) -> bool {
    matches!(
        index.checked_sub(1).and_then(|previous| tokens.get(previous)),
        Some(Token {
            kind: TokenKind::Punct(actual),
            ..
        }) if *actual == punctuation
    )
}

pub(super) fn dyn_error_follows(tokens: &[Token], index: usize) -> bool {
    tokens[index + 1..]
        .iter()
        .take_while(|token| !matches!(token.kind, TokenKind::Punct('>') | TokenKind::Punct(',')))
        .any(|token| token.kind.as_ident() == Some("Error"))
}

pub(super) fn next_is_bang(tokens: &[Token], index: usize) -> bool {
    matches!(
        tokens.get(index + 1),
        Some(Token {
            kind: TokenKind::Punct('!'),
            ..
        })
    )
}

pub(super) fn is_identifier_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

pub(super) fn is_identifier_continue(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

pub(super) fn line_comment_texts(content: &str) -> Vec<Option<LineComment>> {
    let chars: Vec<char> = content.chars().collect();
    let mut comments = Vec::new();
    let mut index = 0;
    let mut line = 1;
    let mut line_has_code = false;
    let mut state = ScannerState::Code;

    while index < chars.len() {
        ensure_comment_line(&mut comments, line);
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            ScannerState::Code => {
                if ch == '/' && next == Some('/') {
                    let mut cursor = index + 2;
                    let mut comment = String::new();
                    while cursor < chars.len() && chars[cursor] != '\n' {
                        comment.push(chars[cursor]);
                        cursor += 1;
                    }
                    comments[line - 1] = Some(LineComment {
                        text: comment,
                        is_line_leading: !line_has_code,
                    });
                    index = cursor;
                } else if ch == '/' && next == Some('*') {
                    index += 2;
                    state = ScannerState::BlockComment(1);
                } else if ch == '"' {
                    line_has_code = true;
                    index += 1;
                    state = ScannerState::String;
                } else if let Some(end) = char_literal_end(&chars, index) {
                    line_has_code = true;
                    if advance_line_count(&chars[index..end], &mut line) {
                        line_has_code = false;
                    }
                    index = end;
                } else if let Some(end) = raw_string_end(&chars, index) {
                    line_has_code = true;
                    if advance_line_count(&chars[index..end], &mut line) {
                        line_has_code = false;
                    }
                    index = end;
                } else {
                    if ch == '\n' {
                        line += 1;
                        line_has_code = false;
                    } else if !ch.is_whitespace() {
                        line_has_code = true;
                    }
                    index += 1;
                }
            }
            ScannerState::LineComment => {
                if ch == '\n' {
                    line += 1;
                    line_has_code = false;
                    state = ScannerState::Code;
                }
                index += 1;
            }
            ScannerState::BlockComment(depth) => {
                if ch == '/' && next == Some('*') {
                    index += 2;
                    state = ScannerState::BlockComment(depth + 1);
                } else if ch == '*' && next == Some('/') {
                    index += 2;
                    if depth == 1 {
                        state = ScannerState::Code;
                    } else {
                        state = ScannerState::BlockComment(depth - 1);
                    }
                } else {
                    if ch == '\n' {
                        line += 1;
                        line_has_code = false;
                    }
                    index += 1;
                }
            }
            ScannerState::String => {
                if ch == '\\' && next.is_some() {
                    if next == Some('\n') {
                        line += 1;
                        line_has_code = false;
                    }
                    index += 2;
                } else if ch == '"' {
                    index += 1;
                    state = ScannerState::Code;
                } else {
                    if ch == '\n' {
                        line += 1;
                        line_has_code = false;
                    }
                    index += 1;
                }
            }
        }
    }

    if comments.is_empty() {
        comments.push(None);
    }

    comments
}

pub(super) fn ensure_comment_line(comments: &mut Vec<Option<LineComment>>, line: usize) {
    if comments.len() < line {
        comments.resize_with(line, || None);
    }
}

pub(super) fn advance_line_count(chars: &[char], line: &mut usize) -> bool {
    let newline_count = chars.iter().filter(|ch| **ch == '\n').count();
    *line += newline_count;
    newline_count > 0
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Token {
    pub(super) kind: TokenKind,
    pub(super) line: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BindingRef<'a> {
    pub(super) name: &'a str,
    pub(super) line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AttributeText {
    pub(super) normalized: String,
    pub(super) end_line: usize,
    pub(super) end_column: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LineComment {
    pub(super) text: String,
    pub(super) is_line_leading: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TokenKind {
    Ident(String),
    Punct(char),
}

impl TokenKind {
    pub(super) fn as_ident(&self) -> Option<&str> {
        match self {
            Self::Ident(identifier) => Some(identifier),
            Self::Punct(_) => None,
        }
    }
}

pub(super) fn scrub_comments_and_strings(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut index = 0;
    let mut state = ScannerState::Code;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            ScannerState::Code => {
                if ch == '/' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::LineComment;
                } else if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(1);
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::String;
                } else if let Some(end) = char_literal_end(&chars, index) {
                    replace_range_with_spaces(&chars, index, end, &mut out);
                    index = end;
                } else if let Some(end) = raw_string_end(&chars, index) {
                    replace_range_with_spaces(&chars, index, end, &mut out);
                    index = end;
                } else {
                    out.push(ch);
                    index += 1;
                }
            }
            ScannerState::LineComment => {
                if ch == '\n' {
                    out.push('\n');
                    state = ScannerState::Code;
                } else {
                    out.push(' ');
                }
                index += 1;
            }
            ScannerState::BlockComment(depth) => {
                if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(depth + 1);
                } else if ch == '*' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    if depth == 1 {
                        state = ScannerState::Code;
                    } else {
                        state = ScannerState::BlockComment(depth - 1);
                    }
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
            ScannerState::String => {
                if ch == '\\' && next.is_some() {
                    out.push(' ');
                    out.push(if next == Some('\n') { '\n' } else { ' ' });
                    index += 2;
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::Code;
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
        }
    }

    out
}

pub(super) fn raw_string_end(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start) != Some(&'r') {
        return None;
    }

    let mut cursor = start + 1;
    let mut hashes = 0;
    while chars.get(cursor) == Some(&'#') {
        hashes += 1;
        cursor += 1;
    }
    if chars.get(cursor) != Some(&'"') {
        return None;
    }
    cursor += 1;

    while cursor < chars.len() {
        if chars[cursor] == '"' {
            let hash_end = cursor + 1 + hashes;
            if hash_end <= chars.len() && chars[cursor + 1..hash_end].iter().all(|ch| *ch == '#') {
                return Some(hash_end);
            }
        }
        cursor += 1;
    }

    Some(chars.len())
}

pub(super) fn char_literal_end(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start) != Some(&'\'') {
        return None;
    }

    let mut cursor = start + 1;
    if chars.get(cursor) == Some(&'\\') {
        cursor += 2;
    } else {
        cursor += 1;
    }

    if chars.get(cursor) == Some(&'\'') {
        Some(cursor + 1)
    } else {
        None
    }
}

pub(super) fn replace_range_with_spaces(
    chars: &[char],
    start: usize,
    end: usize,
    out: &mut String,
) {
    for ch in &chars[start..end] {
        out.push(if *ch == '\n' { '\n' } else { ' ' });
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ScannerState {
    Code,
    LineComment,
    BlockComment(usize),
    String,
}

pub(super) fn assert_contains(findings: &[String], reason: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(reason)),
        "expected finding containing `{reason}`, got {findings:?}"
    );
}
