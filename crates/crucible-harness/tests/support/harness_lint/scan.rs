//! Shared support for `scan`.

use super::*;

pub(super) fn scan_content(path: &Path, content: &str) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Ident(identifier) = &token.kind else {
            continue;
        };

        match identifier.as_str() {
            "SystemTime" => push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "host wall-clock",
                "SystemTime",
                "host-wall-clock",
            ),
            "Instant" => push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "host monotonic time",
                "Instant",
                "host-monotonic-time",
            ),
            "thread_rng" => push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "thread/global RNG",
                "thread_rng",
                "thread-global-rng",
            ),
            "rng" if previous_path_identifier(&tokens, index) == Some("rand") => push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "thread/global RNG",
                "rand::rng",
                "thread-global-rng",
            ),
            "from_entropy"
                if matches!(
                    previous_path_identifier(&tokens, index),
                    Some("StdRng" | "SmallRng")
                ) =>
            {
                push_finding(
                    &mut findings,
                    path,
                    content,
                    token.line,
                    "thread/global RNG",
                    "from_entropy",
                    "thread-global-rng",
                );
            }
            "OsRng" => push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "host RNG",
                "OsRng",
                "host-rng",
            ),
            "getrandom" => push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "host RNG",
                "getrandom",
                "host-rng",
            ),
            "HashMap" | "HashSet" => push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "unordered map/set",
                identifier,
                "unordered-map-set",
            ),
            "DefaultHasher" | "RandomState" => push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "default/random hasher",
                identifier,
                "default-random-hasher",
            ),
            "select"
                if next_is_bang(&tokens, index) && select_macro_is_unordered(&tokens, index) =>
            {
                push_finding(
                    &mut findings,
                    path,
                    content,
                    token.line,
                    "nondeterministic select",
                    "select!",
                    "nondeterministic-select",
                )
            }
            _ => {}
        }
    }

    findings
}

pub(super) fn custom_static_analysis_failures(path: &Path, content: &str) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let hash_containers = hash_container_bindings(&tokens);

    let mut findings = hash_container_iteration_failures(path, content, &tokens, &hash_containers);
    findings.extend(default_random_hasher_failures(path, content, &tokens));
    findings.extend(unordered_select_failures(path, content, &tokens));
    findings.extend(bare_unsafe_block_failures(path, content, &tokens));
    findings.extend(allow_annotation_failures(path, content));
    findings
}

pub(super) fn default_random_hasher_failures(
    path: &Path,
    content: &str,
    tokens: &[Token],
) -> Vec<String> {
    let mut findings = Vec::new();

    for token in tokens {
        let Some(identifier) = token.kind.as_ident() else {
            continue;
        };
        if matches!(identifier, "DefaultHasher" | "RandomState") {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "default/random hasher",
                identifier,
                "default-random-hasher",
            );
        }
    }

    findings
}

pub(super) fn hash_container_bindings(tokens: &[Token]) -> BTreeSet<String> {
    let mut bindings = BTreeSet::new();

    for (index, token) in tokens.iter().enumerate() {
        let Some(identifier) = token.kind.as_ident() else {
            continue;
        };

        if identifier == "let" {
            if let Some(binding) = let_binding_with_hash_container(tokens, index) {
                bindings.insert(binding);
            }
            continue;
        }

        if token_starts_hash_container_type_annotation(tokens, index) {
            bindings.insert(identifier.to_string());
        }
    }

    bindings
}

pub(super) fn let_binding_with_hash_container(tokens: &[Token], index: usize) -> Option<String> {
    let mut cursor = index + 1;
    if tokens.get(cursor).and_then(|token| token.kind.as_ident()) == Some("mut") {
        cursor += 1;
    }

    let binding = tokens.get(cursor)?.kind.as_ident()?.to_string();
    statement_contains_hash_container(tokens, cursor).then_some(binding)
}

pub(super) fn token_starts_hash_container_type_annotation(tokens: &[Token], index: usize) -> bool {
    let Some(Token {
        kind: TokenKind::Punct(':'),
        ..
    }) = tokens.get(index + 1)
    else {
        return false;
    };

    tokens[index + 2..]
        .iter()
        .take_while(|token| {
            !matches!(
                token.kind,
                TokenKind::Punct(',') | TokenKind::Punct(')') | TokenKind::Punct(';')
            )
        })
        .any(token_is_hash_container)
}

pub(super) fn statement_contains_hash_container(tokens: &[Token], index: usize) -> bool {
    tokens[index..]
        .iter()
        .take_while(|token| !matches!(token.kind, TokenKind::Punct(';')))
        .any(token_is_hash_container)
}

pub(super) fn token_is_hash_container(token: &Token) -> bool {
    matches!(token.kind.as_ident(), Some("HashMap" | "HashSet"))
}

pub(super) fn hash_container_iteration_failures(
    path: &Path,
    content: &str,
    tokens: &[Token],
    hash_containers: &BTreeSet<String>,
) -> Vec<String> {
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let Some(identifier) = token.kind.as_ident() else {
            continue;
        };

        if HASH_ITERATION_METHODS.contains(&identifier)
            && previous_is_punct(tokens, index, '.')
            && method_target_is_hash_container(tokens, index, hash_containers)
        {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "unordered hash-container iteration",
                &format!(".{identifier}()"),
                "hash-iteration",
            );
        }

        if identifier == "for" {
            findings.extend(for_loop_hash_iteration_failure(
                path,
                content,
                tokens,
                index,
                hash_containers,
            ));
        }
    }

    findings
}

pub(super) fn method_target_is_hash_container(
    tokens: &[Token],
    method_index: usize,
    hash_containers: &BTreeSet<String>,
) -> bool {
    let Some(target_index) = method_index.checked_sub(2) else {
        return false;
    };

    tokens
        .get(target_index)
        .and_then(|token| token.kind.as_ident())
        .is_some_and(|target| hash_containers.contains(target))
}

pub(super) fn for_loop_hash_iteration_failure(
    path: &Path,
    content: &str,
    tokens: &[Token],
    for_index: usize,
    hash_containers: &BTreeSet<String>,
) -> Vec<String> {
    let Some(in_index) = tokens[for_index + 1..]
        .iter()
        .position(|token| token.kind.as_ident() == Some("in"))
        .map(|relative| for_index + 1 + relative)
    else {
        return Vec::new();
    };

    let Some(iterated) = for_loop_iterated_binding(tokens, in_index + 1) else {
        return Vec::new();
    };

    if hash_containers.contains(iterated.name) {
        let mut findings = Vec::new();
        push_finding(
            &mut findings,
            path,
            content,
            iterated.line,
            "unordered hash-container iteration",
            &format!("for ... in {}", iterated.name),
            "hash-iteration",
        );
        findings
    } else {
        Vec::new()
    }
}

pub(super) fn for_loop_iterated_binding(
    tokens: &[Token],
    mut index: usize,
) -> Option<BindingRef<'_>> {
    loop {
        match tokens.get(index) {
            Some(Token {
                kind: TokenKind::Punct('&'),
                ..
            }) => index += 1,
            Some(Token {
                kind: TokenKind::Ident(identifier),
                ..
            }) if identifier == "mut" => index += 1,
            _ => break,
        }
    }

    tokens.get(index).and_then(|token| {
        token.kind.as_ident().map(|name| BindingRef {
            name,
            line: token.line,
        })
    })
}

pub(super) fn unordered_select_failures(
    path: &Path,
    content: &str,
    tokens: &[Token],
) -> Vec<String> {
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() == Some("select")
            && next_is_bang(tokens, index)
            && select_macro_is_unordered(tokens, index)
        {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "unordered select",
                "select!",
                "unordered-select",
            );
        }
    }

    findings
}

pub(super) fn select_macro_is_unordered(tokens: &[Token], index: usize) -> bool {
    let Some(open_brace) = tokens[index + 1..]
        .iter()
        .position(|token| matches!(token.kind, TokenKind::Punct('{')))
        .map(|relative| index + 1 + relative)
    else {
        return true;
    };

    !matches!(
        (
            tokens
                .get(open_brace + 1)
                .and_then(|token| token.kind.as_ident()),
            tokens.get(open_brace + 2),
        ),
        (
            Some("biased"),
            Some(Token {
                kind: TokenKind::Punct(';'),
                ..
            })
        )
    )
}

pub(super) fn bare_unsafe_block_failures(
    path: &Path,
    content: &str,
    tokens: &[Token],
) -> Vec<String> {
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() == Some("unsafe")
            && unsafe_block_follows(tokens, index)
            && !has_immediately_preceding_safety_comment(content, token.line)
        {
            findings.push(finding(path, token.line, "bare unsafe block", "unsafe"));
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

pub(super) fn has_immediately_preceding_safety_comment(content: &str, line: usize) -> bool {
    let Some(previous_line) = line.checked_sub(2) else {
        return false;
    };

    content
        .lines()
        .nth(previous_line)
        .is_some_and(|candidate| candidate.trim_start().starts_with("// SAFETY:"))
}
