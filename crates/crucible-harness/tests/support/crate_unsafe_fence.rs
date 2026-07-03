//! Shared unsafe-fence scanner support.

use super::*;

pub(super) fn crate_root_inner_attributes(source: &str) -> Vec<&str> {
    let mut attrs = Vec::new();
    let mut in_block_comment = false;

    for line in source.lines() {
        let trimmed = line.trim();

        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with("//!") {
            continue;
        }

        if trimmed.starts_with("//") {
            continue;
        }

        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }

        if let Some(attribute) = active_inner_attribute(trimmed) {
            attrs.push(attribute);
            continue;
        }

        break;
    }

    attrs
}

pub(super) fn active_inner_attribute(line: &str) -> Option<&str> {
    let candidate = match line.split_once("//") {
        Some((before_comment, _comment)) => before_comment.trim_end(),
        None => line,
    };

    candidate.strip_prefix("#![")?;
    Some(candidate)
}

pub(super) fn unsafe_source_failures(
    path: &Path,
    content: &str,
    unsafe_boundary: bool,
) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() != Some("unsafe") {
            continue;
        }

        let has_safety_comment = has_adjacent_safety_comment(content, token.line);
        if !unsafe_boundary {
            if is_test_source(path) && has_safety_comment {
                continue;
            }
            findings.push(finding(
                path,
                token.line,
                "unsafe keyword outside enumerated unsafe-boundary crate",
                "unsafe",
            ));
            continue;
        }

        let has_safety_section = has_preceding_safety_section(content, token.line);
        if unsafe_callable_item_at(&tokens, index) && !has_safety_section {
            findings.push(finding(path, token.line, "unsafe item", "unsafe"));
        }

        if unsafe_impl_at(&tokens, index) && !has_safety_comment {
            findings.push(finding(
                path,
                token.line,
                "unsafe impl without SAFETY",
                "unsafe impl",
            ));
        }

        if unsafe_block_follows(&tokens, index) && !has_safety_comment {
            findings.push(finding(path, token.line, "bare unsafe block", "unsafe"));
        }

        if public_unsafe_api_at(&tokens, index) && !has_safety_section {
            findings.push(finding(path, token.line, "public unsafe API", "unsafe"));
        }

        findings.extend(public_unsafe_extern_item_failures(path, &tokens, index));
    }

    findings
}

fn is_test_source(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "tests")
}

pub(super) fn unsafe_callable_item_at(tokens: &[Token], unsafe_index: usize) -> bool {
    matches!(unsafe_item_kind(tokens, unsafe_index), Some("fn" | "trait"))
        || unsafe_extern_function_at(tokens, unsafe_index)
}

pub(super) fn unsafe_impl_at(tokens: &[Token], unsafe_index: usize) -> bool {
    unsafe_item_kind(tokens, unsafe_index) == Some("impl")
}

pub(super) fn public_unsafe_api_at(tokens: &[Token], unsafe_index: usize) -> bool {
    item_prefix_contains_pub(tokens, unsafe_index)
        && matches!(
            unsafe_item_kind(tokens, unsafe_index),
            Some("fn" | "trait" | "extern")
        )
}

pub(super) fn unsafe_item_kind(tokens: &[Token], unsafe_index: usize) -> Option<&str> {
    let next = tokens.get(unsafe_index + 1)?.kind.as_ident()?;
    match next {
        "fn" | "trait" => Some(next),
        "impl" => Some("impl"),
        "extern" => Some("extern"),
        _ => None,
    }
}

pub(super) fn unsafe_extern_function_at(tokens: &[Token], unsafe_index: usize) -> bool {
    if unsafe_item_kind(tokens, unsafe_index) != Some("extern") {
        return false;
    }

    tokens[unsafe_index + 1..]
        .iter()
        .take_while(|token| !matches!(token.kind, TokenKind::Punct('{') | TokenKind::Punct(';')))
        .any(|token| token.kind.as_ident() == Some("fn"))
}

pub(super) fn item_prefix_contains_pub(tokens: &[Token], index: usize) -> bool {
    let mut cursor = index;
    while let Some(previous) = cursor.checked_sub(1) {
        let token = &tokens[previous];
        match &token.kind {
            TokenKind::Ident(identifier) if identifier == "pub" => return true,
            TokenKind::Punct(';' | '{' | '}') => return false,
            _ => cursor = previous,
        }
    }

    false
}

pub(super) fn public_unsafe_extern_item_failures(
    path: &Path,
    tokens: &[Token],
    unsafe_index: usize,
) -> Vec<String> {
    if unsafe_item_kind(tokens, unsafe_index) != Some("extern") {
        return Vec::new();
    }

    let Some(open_brace) = tokens[unsafe_index + 1..]
        .iter()
        .position(|token| matches!(token.kind, TokenKind::Punct('{')))
        .map(|relative| unsafe_index + 1 + relative)
    else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let mut depth = 0usize;
    for token in &tokens[open_brace..] {
        match token.kind {
            TokenKind::Punct('{') => depth += 1,
            TokenKind::Punct('}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }

        if depth == 1 && token.kind.as_ident() == Some("pub") {
            findings.push(finding(
                path,
                token.line,
                "public unsafe extern item",
                "pub item",
            ));
        }
    }

    findings
}

pub(super) fn unsafe_block_follows(tokens: &[Token], index: usize) -> bool {
    matches!(
        tokens.get(index + 1),
        Some(Token {
            kind: TokenKind::Punct('{'),
            ..
        })
    )
}

pub(super) fn has_adjacent_safety_comment(content: &str, line: usize) -> bool {
    has_preceding_safety_comment(content, line) || has_following_safety_comment(content, line)
}

pub(super) fn has_preceding_safety_comment(content: &str, line: usize) -> bool {
    let Some(mut cursor) = line.checked_sub(1) else {
        return false;
    };

    let lines = content.lines().collect::<Vec<_>>();
    while let Some(index) = cursor.checked_sub(1) {
        let candidate = lines[index].trim_start();
        if !candidate.starts_with("//") {
            return false;
        }
        if safety_comment_states_invariant(candidate) {
            return true;
        }
        cursor = index;
    }

    false
}

pub(super) fn has_following_safety_comment(content: &str, line: usize) -> bool {
    content
        .lines()
        .nth(line)
        .is_some_and(safety_comment_states_invariant)
}

pub(super) fn has_preceding_safety_section(content: &str, line: usize) -> bool {
    let Some(mut cursor) = line.checked_sub(1) else {
        return false;
    };

    let lines = content.lines().collect::<Vec<_>>();
    while let Some(index) = cursor.checked_sub(1) {
        let candidate = lines[index].trim_start();
        if candidate.starts_with("///") || candidate.starts_with("//!") {
            if candidate.contains("# Safety") {
                return true;
            }
            cursor = index;
            continue;
        }
        if candidate.starts_with("#[") || candidate.is_empty() {
            cursor = index;
            continue;
        }
        return false;
    }

    false
}

pub(super) fn safety_comment_states_invariant(candidate: &str) -> bool {
    let Some(invariant) = candidate.trim_start().strip_prefix("// SAFETY:") else {
        return false;
    };

    !invariant.trim().is_empty()
}

pub(super) fn rust_sources(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut sources = Vec::new();
    collect_rust_sources(dir, &mut sources)?;
    sources.sort();
    Ok(sources)
}

pub(super) fn collect_rust_sources(
    dir: &Path,
    sources: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            sources.push(path);
        }
    }
    Ok(())
}

pub(super) fn workspace_crates_dir() -> Result<PathBuf, io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("crucible-harness manifest is not inside crates/"))
}

pub(super) fn assert_expected_crucible_package_set(
    crates_dir: &Path,
    failures: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut expected: Vec<String> = FENCE_SPECS
        .iter()
        .map(|spec| spec.package.to_string())
        .collect();
    expected.sort();

    let mut found = Vec::new();
    for entry in fs::read_dir(crates_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !path.join("Cargo.toml").is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("crucible") {
            found.push(name);
        }
    }
    found.sort();

    if found != expected {
        failures.push(format!(
            "crucible package set mismatch: expected [{}], found [{}]",
            expected.join(", "),
            found.join(", ")
        ));
    }

    Ok(())
}

pub(super) fn display_repo_path(path: &Path) -> String {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new(""));
    path.strip_prefix(crates_dir)
        .map(|relative| format!("crates/{}", relative.display()))
        .unwrap_or_else(|_| path.display().to_string())
}

pub(super) fn finding(path: &Path, line: usize, reason: &str, pattern: &str) -> String {
    format!(
        "{}:{line}: banned {reason} pattern `{pattern}`",
        display_repo_path(path)
    )
}

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

pub(super) fn is_identifier_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

pub(super) fn is_identifier_continue(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Token {
    kind: TokenKind,
    line: usize,
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
