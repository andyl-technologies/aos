//! Shared support for `scan`.

use super::*;

#[path = "guidance.rs"]
mod guidance;

pub(super) fn scan_content(path: &Path, content: &str) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let cfg_test_ranges = cfg_test_line_ranges(content);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if line_in_ranges(token.line, &cfg_test_ranges) {
            continue;
        }

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
    findings.extend(fault_apply_path_failures(path, content));
    findings.extend(distribution_metadata_flow_failures(path, content, &tokens));
    findings.extend(guidance::guidance_ordering_float_failures(
        path, content, &tokens,
    ));
    findings.extend(allow_annotation_failures(path, content));
    filter_cfg_test_findings(content, findings)
}

const INJECT_ACTIVE_FAULTS_EFFECT: &[TokenNeedle] = &[
    TokenNeedle::Ident("state"),
    TokenNeedle::Punct('.'),
    TokenNeedle::Ident("active_faults"),
    TokenNeedle::Punct('.'),
    TokenNeedle::Ident("insert"),
    TokenNeedle::Punct('('),
    TokenNeedle::Ident("tag"),
    TokenNeedle::Punct('.'),
    TokenNeedle::Ident("clone"),
    TokenNeedle::Punct('('),
    TokenNeedle::Punct(')'),
    TokenNeedle::Punct(','),
    TokenNeedle::Ident("fault"),
    TokenNeedle::Punct('.'),
    TokenNeedle::Ident("clone"),
    TokenNeedle::Punct('('),
    TokenNeedle::Punct(')'),
    TokenNeedle::Punct(')'),
];
const HEAL_ACTIVE_FAULTS_EFFECT: &[TokenNeedle] = &[
    TokenNeedle::Ident("state"),
    TokenNeedle::Punct('.'),
    TokenNeedle::Ident("active_faults"),
    TokenNeedle::Punct('.'),
    TokenNeedle::Ident("remove"),
    TokenNeedle::Punct('('),
    TokenNeedle::Ident("tag"),
    TokenNeedle::Punct(')'),
];
const INJECT_ACTIVE_FAULTS_CALL_OFFSETS: &[usize] = &[4, 8, 14];
const HEAL_ACTIVE_FAULTS_CALL_OFFSETS: &[usize] = &[4];
const INJECT_ACTIVE_FAULTS_HELPER_CALL: &[TokenNeedle] = &[
    TokenNeedle::Ident("activate_fault_tag"),
    TokenNeedle::Punct('('),
    TokenNeedle::Ident("state"),
    TokenNeedle::Punct(','),
    TokenNeedle::Ident("tag"),
    TokenNeedle::Punct(','),
    TokenNeedle::Ident("fault"),
    TokenNeedle::Punct(')'),
];
const HEAL_ACTIVE_FAULTS_HELPER_CALL: &[TokenNeedle] = &[
    TokenNeedle::Ident("heal_fault_tag"),
    TokenNeedle::Punct('('),
    TokenNeedle::Ident("state"),
    TokenNeedle::Punct(','),
    TokenNeedle::Ident("tag"),
    TokenNeedle::Punct(')'),
];
const FAULT_HELPER_CALL_OFFSETS: &[usize] = &[0];

const FAULT_APPLY_REQUIRED_PATTERNS: &[FaultApplyRequiredPattern] = &[
    FaultApplyRequiredPattern {
        variant: "InjectFault",
        label: "state.active_faults.insert(tag.clone(), fault.clone())",
        pattern: INJECT_ACTIVE_FAULTS_EFFECT,
        call_offsets: INJECT_ACTIVE_FAULTS_CALL_OFFSETS,
        helper_name: "activate_fault_tag",
        helper_pattern: INJECT_ACTIVE_FAULTS_HELPER_CALL,
        helper_call_offsets: FAULT_HELPER_CALL_OFFSETS,
    },
    FaultApplyRequiredPattern {
        variant: "HealFault",
        label: "state.active_faults.remove(tag)",
        pattern: HEAL_ACTIVE_FAULTS_EFFECT,
        call_offsets: HEAL_ACTIVE_FAULTS_CALL_OFFSETS,
        helper_name: "heal_fault_tag",
        helper_pattern: HEAL_ACTIVE_FAULTS_HELPER_CALL,
        helper_call_offsets: FAULT_HELPER_CALL_OFFSETS,
    },
];

const FAULT_APPLY_FORBIDDEN_PATTERNS: &[&str] = &[
    "SystemTime",
    "Instant",
    "thread_rng",
    "rand::rng",
    "rand::random",
    "from_entropy",
    "OsRng",
    "getrandom",
    "std::fs",
    "fs::",
    "File::",
    "read_dir",
    "metadata",
    "std::thread",
    "thread::",
    "spawn",
    "sleep",
    "yield_now",
    "trigger_static_topology",
    "effective_topology",
    "topology_changes",
    "lookahead_graph",
    "SchedulerLookaheadGraph",
    "WorldStaticTopology",
    "with_effective_topology_edges",
];

#[derive(Clone, Copy)]
struct FaultApplyRequiredPattern {
    variant: &'static str,
    label: &'static str,
    pattern: &'static [TokenNeedle],
    call_offsets: &'static [usize],
    helper_name: &'static str,
    helper_pattern: &'static [TokenNeedle],
    helper_call_offsets: &'static [usize],
}

#[derive(Clone, Copy)]
enum TokenNeedle {
    Ident(&'static str),
    Punct(char),
}

pub(super) fn fault_apply_path_failures(path: &Path, content: &str) -> Vec<String> {
    if !content.contains("fn apply_trigger_effect(") {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let Some(function_range) = function_token_range(&tokens, "apply_trigger_effect") else {
        let line = content
            .find("fn apply_trigger_effect(")
            .map_or(1, |offset| line_for_offset(content, offset));
        findings.push(finding(
            path,
            line,
            "unrecognizable fault apply path",
            "apply_trigger_effect",
        ));
        return findings;
    };
    let mut helper_requirements = Vec::new();

    for required in FAULT_APPLY_REQUIRED_PATTERNS {
        let Some(arm_range) =
            action_arm_body_range(&tokens, function_range.clone(), required.variant)
        else {
            findings.push(finding(
                path,
                token_range_line(&tokens, &function_range),
                "unrecognizable fault apply path",
                &format!("Action::{}", required.variant),
            ));
            continue;
        };

        let mut allowed_call_indices = BTreeSet::new();
        if let Some(start) = find_token_sequence(&tokens, arm_range.clone(), required.pattern) {
            allowed_call_indices.extend(
                required
                    .call_offsets
                    .iter()
                    .map(|offset| start.saturating_add(*offset)),
            );
        } else if let Some(start) =
            find_token_sequence(&tokens, arm_range.clone(), required.helper_pattern)
        {
            allowed_call_indices.extend(
                required
                    .helper_call_offsets
                    .iter()
                    .map(|offset| start.saturating_add(*offset)),
            );
            helper_requirements.push(*required);
        } else {
            findings.push(finding(
                path,
                token_range_line(&tokens, &arm_range),
                "missing modeled fault-state effect",
                required.label,
            ));
        }

        findings.extend(fault_apply_forbidden_token_failures(
            path,
            &tokens,
            arm_range.clone(),
        ));
        findings.extend(fault_apply_direct_effect_failures(
            path,
            &tokens,
            arm_range,
            &allowed_call_indices,
        ));
    }

    for required in helper_requirements {
        findings.extend(fault_apply_helper_failures(path, &tokens, required));
    }

    findings
}

fn function_token_range(tokens: &[Token], name: &str) -> Option<std::ops::Range<usize>> {
    let fn_index = tokens.windows(2).position(|window| {
        window[0].kind.as_ident() == Some("fn") && window[1].kind.as_ident() == Some(name)
    })?;
    let open_brace = tokens[fn_index + 2..]
        .iter()
        .position(|token| matches!(token.kind, TokenKind::Punct('{')))
        .map(|relative| fn_index + 2 + relative)?;
    let close_brace = matching_brace(tokens, open_brace)?;
    Some(open_brace + 1..close_brace)
}

fn fault_apply_helper_failures(
    path: &Path,
    tokens: &[Token],
    required: FaultApplyRequiredPattern,
) -> Vec<String> {
    let mut findings = Vec::new();
    let Some(helper_range) = function_token_range(tokens, required.helper_name) else {
        findings.push(finding(
            path,
            1,
            "missing modeled fault-state helper",
            required.helper_name,
        ));
        return findings;
    };

    if find_token_sequence(tokens, helper_range.clone(), required.pattern).is_none() {
        findings.push(finding(
            path,
            token_range_line(tokens, &helper_range),
            "missing modeled fault-state effect",
            required.label,
        ));
    }
    findings.extend(fault_apply_forbidden_token_failures(
        path,
        tokens,
        helper_range,
    ));
    findings
}

fn action_arm_body_range(
    tokens: &[Token],
    function_range: std::ops::Range<usize>,
    variant: &str,
) -> Option<std::ops::Range<usize>> {
    let variant_index = find_action_variant(tokens, function_range.clone(), variant)?;
    let arrow_index = find_match_arrow(tokens, variant_index, function_range.end)?;
    let body_open = tokens[arrow_index + 2..function_range.end]
        .iter()
        .position(|token| matches!(token.kind, TokenKind::Punct('{')))
        .map(|relative| arrow_index + 2 + relative)?;
    let body_close = matching_brace(tokens, body_open)?;
    (body_close <= function_range.end).then_some(body_open + 1..body_close)
}

fn find_action_variant(
    tokens: &[Token],
    range: std::ops::Range<usize>,
    variant: &str,
) -> Option<usize> {
    range.into_iter().find(|index| {
        tokens.get(*index).and_then(|token| token.kind.as_ident()) == Some("Action")
            && matches!(
                (tokens.get(index + 1), tokens.get(index + 2)),
                (
                    Some(Token {
                        kind: TokenKind::Punct(':'),
                        ..
                    }),
                    Some(Token {
                        kind: TokenKind::Punct(':'),
                        ..
                    })
                )
            )
            && tokens
                .get(index + 3)
                .and_then(|token| token.kind.as_ident())
                == Some(variant)
    })
}

fn find_match_arrow(tokens: &[Token], start: usize, end: usize) -> Option<usize> {
    (start..end.saturating_sub(1)).find(|index| {
        matches!(
            (tokens.get(*index), tokens.get(index + 1)),
            (
                Some(Token {
                    kind: TokenKind::Punct('='),
                    ..
                }),
                Some(Token {
                    kind: TokenKind::Punct('>'),
                    ..
                })
            )
        )
    })
}

fn matching_brace(tokens: &[Token], open_brace: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open_brace) {
        match token.kind {
            TokenKind::Punct('{') => depth += 1,
            TokenKind::Punct('}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            TokenKind::Ident(_) | TokenKind::Punct(_) => {}
        }
    }
    None
}

fn find_token_sequence(
    tokens: &[Token],
    range: std::ops::Range<usize>,
    pattern: &[TokenNeedle],
) -> Option<usize> {
    range.into_iter().find(|start| {
        pattern.iter().enumerate().all(|(offset, needle)| {
            tokens
                .get(start + offset)
                .is_some_and(|token| token_matches_needle(token, *needle))
        })
    })
}

fn token_matches_needle(token: &Token, needle: TokenNeedle) -> bool {
    match (needle, &token.kind) {
        (TokenNeedle::Ident(expected), TokenKind::Ident(actual)) => actual == expected,
        (TokenNeedle::Punct(expected), TokenKind::Punct(actual)) => *actual == expected,
        (TokenNeedle::Ident(_) | TokenNeedle::Punct(_), _) => false,
    }
}

pub(super) fn distribution_metadata_flow_failures(
    path: &Path,
    content: &str,
    tokens: &[Token],
) -> Vec<String> {
    let mut findings = Vec::new();

    for function in function_body_ranges(tokens) {
        let body_tokens = &tokens[function.body.clone()];
        let metadata_tokens = body_tokens
            .iter()
            .filter(|token| {
                token.kind.as_ident().is_some_and(|identifier| {
                    distribution_metadata_identifier_is_guarded(
                        identifier,
                        &function.name,
                        body_tokens,
                    )
                })
            })
            .collect::<Vec<_>>();
        if metadata_tokens.is_empty() {
            continue;
        }
        let target_identifiers = body_tokens
            .iter()
            .filter_map(|token| token.kind.as_ident())
            .filter(|identifier| DISTRIBUTION_METADATA_FLOW_TARGETS.contains(identifier))
            .collect::<BTreeSet<_>>();
        if target_identifiers.is_empty() {
            continue;
        }
        if distribution_metadata_function_is_coordination_only(&function.name, &target_identifiers)
        {
            continue;
        }

        for token in metadata_tokens {
            let Some(identifier) = token.kind.as_ident() else {
                continue;
            };
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "distribution metadata reaching reduce/Decision/content key/artifact path",
                identifier,
                "distribution-metadata-flow",
            );
        }
    }

    findings
}

fn distribution_metadata_identifier_is_guarded(
    identifier: &str,
    function_name: &str,
    body_tokens: &[Token],
) -> bool {
    if !DISTRIBUTION_METADATA_IDENTIFIERS.contains(&identifier) {
        return false;
    }
    if identifier != "owner" {
        return true;
    }

    distribution_metadata_body_has_coordination_context(function_name, body_tokens)
}

fn distribution_metadata_body_has_coordination_context(
    function_name: &str,
    body_tokens: &[Token],
) -> bool {
    distribution_metadata_name_has_coordination_term(function_name)
        || body_tokens.iter().any(|token| {
            matches!(
                token.kind.as_ident(),
                Some(
                    "host_id"
                        | "host_owner"
                        | "claim_owner"
                        | "lease_owner"
                        | "claim_order"
                        | "claim_timestamp"
                        | "lease_timestamp"
                        | "acquired_at_tick"
                        | "expires_at_tick"
                        | "lease_id"
                )
            )
        })
}

fn distribution_metadata_function_is_coordination_only(
    name: &str,
    target_identifiers: &BTreeSet<&str>,
) -> bool {
    distribution_metadata_name_has_coordination_term(name)
        && target_identifiers
            .iter()
            .all(|target| DISTRIBUTION_METADATA_COORDINATION_ONLY_TARGETS.contains(target))
}

fn distribution_metadata_name_has_coordination_term(name: &str) -> bool {
    let normalized = name.replace('-', "_").to_ascii_lowercase();
    DISTRIBUTION_METADATA_COORDINATION_FUNCTION_TERMS
        .iter()
        .any(|term| normalized.contains(term))
}

fn function_body_ranges(tokens: &[Token]) -> Vec<FunctionBodyRange> {
    let mut functions = Vec::new();
    let mut cursor = 0usize;

    while cursor + 1 < tokens.len() {
        if tokens[cursor].kind.as_ident() != Some("fn") {
            cursor += 1;
            continue;
        }
        let Some(name) = tokens[cursor + 1].kind.as_ident() else {
            cursor += 1;
            continue;
        };
        let Some(open_brace) = tokens[cursor + 2..]
            .iter()
            .position(|token| matches!(token.kind, TokenKind::Punct('{')))
            .map(|relative| cursor + 2 + relative)
        else {
            cursor += 1;
            continue;
        };
        let Some(close_brace) = matching_brace(tokens, open_brace) else {
            cursor = open_brace + 1;
            continue;
        };
        functions.push(FunctionBodyRange {
            name: name.to_string(),
            body: open_brace + 1..close_brace,
        });
        cursor = close_brace + 1;
    }

    functions
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FunctionBodyRange {
    name: String,
    body: std::ops::Range<usize>,
}

fn fault_apply_forbidden_token_failures(
    path: &Path,
    tokens: &[Token],
    range: std::ops::Range<usize>,
) -> Vec<String> {
    let mut findings = Vec::new();

    for index in range {
        let Some(identifier) = tokens.get(index).and_then(|token| token.kind.as_ident()) else {
            continue;
        };
        let reason_and_pattern = match identifier {
            "SystemTime" => Some(("host wall-clock", "SystemTime")),
            "Instant" => Some(("host monotonic time", "Instant")),
            "thread_rng" => Some(("thread/global RNG", "thread_rng")),
            "rng" if previous_path_identifier(tokens, index) == Some("rand") => {
                Some(("thread/global RNG", "rand::rng"))
            }
            "random" if previous_path_identifier(tokens, index) == Some("rand") => {
                Some(("thread/global RNG", "rand::random"))
            }
            "from_entropy" => Some(("thread/global RNG", "from_entropy")),
            "OsRng" => Some(("host RNG", "OsRng")),
            "getrandom" => Some(("host RNG", "getrandom")),
            "fs" if previous_path_identifier(tokens, index) == Some("std") => {
                Some(("host filesystem", "std::fs"))
            }
            "fs" if next_is_path_separator(tokens, index) => Some(("host filesystem", "fs::")),
            "File" if next_is_path_separator(tokens, index) => Some(("host filesystem", "File::")),
            "read_dir" => Some(("host filesystem", "read_dir")),
            "metadata" => Some(("host filesystem", "metadata")),
            "thread" if previous_path_identifier(tokens, index) == Some("std") => {
                Some(("host thread scheduling", "std::thread"))
            }
            "thread" if next_is_path_separator(tokens, index) => {
                Some(("host thread scheduling", "thread::"))
            }
            "spawn" => Some(("host thread scheduling", "spawn")),
            "sleep" => Some(("host thread scheduling", "sleep")),
            "yield_now" => Some(("host thread scheduling", "yield_now")),
            "trigger_static_topology" => Some(("topology mutation", "trigger_static_topology")),
            "effective_topology" => Some(("topology mutation", "effective_topology")),
            "topology_changes" => Some(("topology mutation", "topology_changes")),
            "lookahead_graph" => Some(("topology mutation", "lookahead_graph")),
            "SchedulerLookaheadGraph" => Some(("topology mutation", "SchedulerLookaheadGraph")),
            "WorldStaticTopology" => Some(("topology mutation", "WorldStaticTopology")),
            "with_effective_topology_edges" => {
                Some(("topology mutation", "with_effective_topology_edges"))
            }
            _ => None,
        };

        if let Some((reason, pattern)) = reason_and_pattern {
            debug_assert!(FAULT_APPLY_FORBIDDEN_PATTERNS.contains(&pattern));
            findings.push(finding(path, tokens[index].line, reason, pattern));
        }
    }

    findings
}

fn fault_apply_direct_effect_failures(
    path: &Path,
    tokens: &[Token],
    range: std::ops::Range<usize>,
    allowed_call_indices: &BTreeSet<usize>,
) -> Vec<String> {
    let mut findings = Vec::new();

    for index in range {
        if matches!(
            tokens.get(index),
            Some(Token {
                kind: TokenKind::Punct('='),
                ..
            })
        ) {
            findings.push(finding(
                path,
                tokens[index].line,
                "unmodeled fault apply assignment",
                "=",
            ));
            continue;
        }

        let Some(identifier) = tokens.get(index).and_then(|token| token.kind.as_ident()) else {
            continue;
        };
        if token_starts_call(tokens, index) && !allowed_call_indices.contains(&index) {
            findings.push(finding(
                path,
                tokens[index].line,
                "unmodeled fault apply call",
                identifier,
            ));
        }
    }

    findings
}

fn token_starts_call(tokens: &[Token], index: usize) -> bool {
    matches!(
        tokens.get(index + 1),
        Some(Token {
            kind: TokenKind::Punct('(' | '!'),
            ..
        })
    )
}

fn token_range_line(tokens: &[Token], range: &std::ops::Range<usize>) -> usize {
    tokens.get(range.start).map_or(1, |token| token.line)
}

fn line_for_offset(content: &str, offset: usize) -> usize {
    content[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
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
        if token.kind.as_ident() == Some("unsafe") && unsafe_block_follows(tokens, index) {
            let line =
                source_line_for_identifier(content, token.line, "unsafe").unwrap_or(token.line);
            if !has_adjacent_safety_comment(content, line) {
                findings.push(finding(path, line, "bare unsafe block", "unsafe"));
            }
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

fn source_line_for_identifier(content: &str, token_line: usize, identifier: &str) -> Option<usize> {
    [
        token_line,
        token_line.saturating_add(1),
        token_line.saturating_sub(1),
    ]
    .into_iter()
    .filter(|line| *line > 0)
    .find(|line| {
        content
            .lines()
            .nth(line - 1)
            .is_some_and(|source_line| source_line.contains(identifier))
    })
}
