//! Shared support for `error_logging`.

use super::*;

pub(super) fn manifest_error_dependency_failures(
    package: &str,
    manifest: &str,
    is_library: bool,
) -> Vec<String> {
    if !is_library {
        return Vec::new();
    }

    let scrubbed = scrub_comments_and_strings(manifest);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Ident(identifier) = &token.kind else {
            continue;
        };

        if matches!(identifier.as_str(), "anyhow" | "eyre" | "miette") {
            findings.push(format!(
                "{package}/Cargo.toml:{}: banned erased error dependency `{identifier}` in library crate",
                token.line
            ));
        }

        if identifier == "workspace" && previous_key_identifier(&tokens, index) == Some("anyhow") {
            findings.push(format!(
                "{package}/Cargo.toml:{}: banned erased error dependency `anyhow` in library crate",
                token.line
            ));
        }
    }

    findings
}

pub(super) fn typed_error_policy_failures(
    package: &str,
    manifest: &str,
    sources: &[&str],
    is_library: bool,
) -> Vec<String> {
    if !is_library
        || manifest_declares_dependency(manifest, "thiserror")
        || sources
            .iter()
            .any(|source| source_declares_typed_error(source))
    {
        return Vec::new();
    }

    vec![missing_typed_error_finding(package)]
}

pub(super) fn missing_typed_error_finding(package: &str) -> String {
    format!(
        "{package}/Cargo.toml:1: missing typed error signal `thiserror` dependency or `impl Error for ...` in library crate"
    )
}

pub(super) fn manifest_declares_dependency(manifest: &str, dependency: &str) -> bool {
    let scrubbed = scrub_comments_and_strings(manifest);
    let tokens = tokenize(&scrubbed);
    tokens.iter().enumerate().any(|(index, token)| {
        token.kind.as_ident() == Some(dependency)
            && matches!(
                tokens.get(index + 1),
                Some(Token {
                    kind: TokenKind::Punct('='),
                    ..
                })
            )
    })
}

pub(super) fn source_declares_typed_error(content: &str) -> bool {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);

    tokens.iter().enumerate().any(|(index, token)| {
        matches!(
            token.kind.as_ident(),
            Some("impl") if impl_error_for_follows(&tokens, index)
        ) || matches!(
            token.kind.as_ident(),
            Some("derive") if derive_error_follows(&tokens, index)
        )
    })
}

pub(super) fn impl_error_for_follows(tokens: &[Token], index: usize) -> bool {
    let mut saw_error = false;

    for token in tokens[index + 1..]
        .iter()
        .take_while(|token| !matches!(token.kind, TokenKind::Punct('{') | TokenKind::Punct(';')))
    {
        match token.kind.as_ident() {
            Some("Error") => saw_error = true,
            Some("for") if saw_error => return true,
            _ => {}
        }
    }

    false
}

pub(super) fn derive_error_follows(tokens: &[Token], index: usize) -> bool {
    if !matches!(
        tokens.get(index + 1),
        Some(Token {
            kind: TokenKind::Punct('('),
            ..
        })
    ) {
        return false;
    }

    let mut depth = 0usize;
    for token in &tokens[index + 1..] {
        match &token.kind {
            TokenKind::Punct('(') => depth += 1,
            TokenKind::Punct(')') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return false;
                }
            }
            TokenKind::Ident(identifier) if depth > 0 && identifier == "Error" => return true,
            _ => {}
        }
    }

    false
}

pub(super) fn error_logging_failures(
    path: &Path,
    content: &str,
    is_binary_boundary: bool,
) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Ident(identifier) = &token.kind else {
            continue;
        };

        if matches!(identifier.as_str(), "unwrap" | "expect")
            && previous_is_punct(&tokens, index, '.')
        {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "panic shortcut",
                &format!(".{identifier}()"),
                "panic-shortcut",
            );
        }

        if !is_binary_boundary
            && matches!(identifier.as_str(), "println" | "eprintln" | "print")
            && next_is_bang(&tokens, index)
        {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "direct stdout/stderr diagnostic",
                &format!("{identifier}!"),
                "direct-diagnostic",
            );
        }

        if !is_binary_boundary && matches!(identifier.as_str(), "anyhow" | "eyre" | "miette") {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "erased error",
                identifier,
                "erased-error",
            );
        }

        if !is_binary_boundary && identifier == "bail" && next_is_bang(&tokens, index) {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "erased error",
                "bail!",
                "erased-error",
            );
        }

        if !is_binary_boundary && identifier == "dyn" && dyn_error_follows(&tokens, index) {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "erased error",
                "dyn Error",
                "erased-error",
            );
        }
    }

    findings.extend(result_string_error_failures(
        path,
        content,
        &tokens,
        is_binary_boundary,
    ));

    filter_cfg_test_findings(content, findings)
}

pub(super) fn result_string_error_failures(
    path: &Path,
    content: &str,
    tokens: &[Token],
    is_binary_boundary: bool,
) -> Vec<String> {
    if is_binary_boundary {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut index = 0usize;

    while index < tokens.len() {
        if tokens[index].kind.as_ident() != Some("Result")
            || !matches!(
                tokens.get(index + 1),
                Some(Token {
                    kind: TokenKind::Punct('<'),
                    ..
                })
            )
        {
            index += 1;
            continue;
        }

        let start_line = tokens[index].line;
        let mut depth = 0usize;
        let mut comma_at_depth_one = false;
        let mut error_uses_string = false;

        index += 1;
        while index < tokens.len() {
            match &tokens[index].kind {
                TokenKind::Punct('<') => depth += 1,
                TokenKind::Punct('>') => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                TokenKind::Punct(',') if depth == 1 => comma_at_depth_one = true,
                TokenKind::Ident(identifier) if comma_at_depth_one && identifier == "String" => {
                    error_uses_string = true;
                }
                _ => {}
            }
            index += 1;
        }

        if error_uses_string {
            push_finding(
                &mut findings,
                path,
                content,
                start_line,
                "stringly error",
                "Result<_, String>",
                "stringly-error",
            );
        }

        index += 1;
    }

    findings
}

pub(super) fn finding(path: &Path, line: usize, reason: &str, pattern: &str) -> String {
    format!(
        "{}:{line}: banned {reason} pattern `{pattern}`",
        path.display()
    )
}

pub(super) fn push_finding(
    findings: &mut Vec<String>,
    path: &Path,
    content: &str,
    line: usize,
    reason: &str,
    pattern: &str,
    rule: &str,
) {
    if !has_lint_allow_for_line(content, line, rule) {
        findings.push(finding(path, line, reason, pattern));
    }
}
