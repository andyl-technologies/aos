//! Validates static invariants of Crucible gate evidence references.

use super::*;

/// Returns failures for circular checklist evidence and missing named sources.
///
/// Needle presence is checked by the Nix check-tree evaluator against the exact
/// content expression supplied to `failuresFor`. That distinction matters for a
/// split Rust module whose check intentionally concatenates several source files.
///
/// # Errors
///
/// Returns an error when the Crucible check directory or a referenced source
/// cannot be read.
pub(super) fn gate_reference_integrity_failures(
    repo: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut checks = Vec::new();
    collect_nix_sources(&repo.join("tests/crucible"), &mut checks)?;
    checks.sort();

    let mut failures = Vec::new();
    for check in checks {
        let content = fs::read_to_string(&check)?;
        failures.extend(checklist_state_needle_failures(&check, &content));
        failures.extend(missing_source_label_failures(repo, &check, &content));
        failures.extend(task_metadata_state_failures(repo, &check, &content)?);
    }
    Ok(failures)
}

pub(super) fn checklist_state_needle_failures(path: &Path, content: &str) -> Vec<String> {
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let line = line.trim();
            line.starts_with("needle = \"- [x] **T-") || line.starts_with("needle = \"- [ ] **T-")
        })
        .map(|(index, line)| {
            format!(
                "{}:{}: checklist state is bookkeeping, not gate evidence: {}",
                path.display(),
                index + 1,
                line.trim()
            )
        })
        .collect()
}

pub(super) fn terminal_outcome_construction_failures(content: &str) -> Vec<String> {
    let tokens = tokenize(&scrub_comments_and_strings(content));
    let patterns = terminal_matches_pattern_ranges(&tokens);
    let functions = terminal_function_ranges(&tokens);
    let mut failures = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() != Some("Outcome")
            || !terminal_token_is_punct(&tokens, index + 1, ':')
            || !terminal_token_is_punct(&tokens, index + 2, ':')
            || patterns.iter().any(|range| range.contains(&index))
        {
            continue;
        }

        let owner = functions
            .iter()
            .rev()
            .find(|(_, range)| range.contains(&index))
            .map(|(name, _)| *name);
        // Actor failures must still become terminal if checkpoint capture fails.
        // That pre-existing Engine fallback may publish only a crash outcome.
        let actor_crash = owner == Some("stop_after_actor_crash")
            && tokens
                .get(index + 3)
                .and_then(|token| token.kind.as_ident())
                == Some("Crashed");
        if owner != Some("enter_stopped") && !actor_crash {
            failures.push(format!(
                "line {} constructs a terminal Outcome outside enter_stopped or the Engine actor-crash fallback",
                token.line
            ));
        }
    }
    failures
}

fn terminal_token_is_punct(tokens: &[Token], index: usize, punctuation: char) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.kind == TokenKind::Punct(punctuation))
}

fn terminal_function_ranges(tokens: &[Token]) -> Vec<(&str, std::ops::Range<usize>)> {
    let mut functions = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() != Some("fn") {
            continue;
        }
        let Some(name) = tokens
            .get(index + 1)
            .and_then(|token| token.kind.as_ident())
        else {
            continue;
        };
        let Some(start) = (index + 2..tokens.len()).find(|offset| {
            terminal_token_is_punct(tokens, *offset, '{')
                || terminal_token_is_punct(tokens, *offset, ';')
        }) else {
            continue;
        };
        if terminal_token_is_punct(tokens, start, ';') {
            continue;
        }
        let mut depth = 0usize;
        for end in start..tokens.len() {
            if terminal_token_is_punct(tokens, end, '{') {
                depth += 1;
            } else if terminal_token_is_punct(tokens, end, '}') {
                depth -= 1;
                if depth == 0 {
                    functions.push((name, start..end + 1));
                    break;
                }
            }
        }
    }
    functions
}

/// Identifies only matches! patterns, excluding the evaluated input and guard.
fn terminal_matches_pattern_ranges(tokens: &[Token]) -> Vec<std::ops::Range<usize>> {
    let mut patterns = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() != Some("matches")
            || !terminal_token_is_punct(tokens, index + 1, '!')
        {
            continue;
        }
        let closing = match tokens.get(index + 2).map(|token| &token.kind) {
            Some(TokenKind::Punct('(')) => ')',
            Some(TokenKind::Punct('[')) => ']',
            Some(TokenKind::Punct('{')) => '}',
            _ => continue,
        };
        let mut depth = 1usize;
        let mut pattern_start = None;
        for offset in index + 3..tokens.len() {
            if depth == 1
                && (terminal_token_is_punct(tokens, offset, closing)
                    || tokens[offset].kind.as_ident() == Some("if"))
            {
                if let Some(start) = pattern_start {
                    patterns.push(start..offset);
                }
                break;
            }
            if depth == 1 && terminal_token_is_punct(tokens, offset, ',') {
                pattern_start.get_or_insert(offset + 1);
            }
            match tokens[offset].kind {
                TokenKind::Punct('(' | '{' | '[') => depth += 1,
                TokenKind::Punct(')' | '}' | ']') => depth -= 1,
                _ => {}
            }
        }
    }
    patterns
}

fn missing_source_label_failures(repo: &Path, check: &Path, content: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let mut offset = 0;

    while let Some(relative) = content[offset..].find("failuresFor \"") {
        let call_start = offset + relative;
        let path_start = call_start + "failuresFor ".len();
        let Some((file_label, after_label)) = parse_double_quoted(content, path_start) else {
            failures.push(format!(
                "{}: malformed literal `failuresFor` file label",
                check.display()
            ));
            offset = path_start + 1;
            continue;
        };

        if is_repository_path(&file_label) {
            let source_path = repo.join(&file_label);
            if !source_path.is_file() {
                failures.push(format!(
                    "{}: evidence source `{file_label}` does not exist",
                    check.display()
                ));
            }
        }

        offset = after_label;
    }

    failures
}

fn collect_nix_sources(dir: &Path, sources: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_nix_sources(&path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("nix") {
            sources.push(path);
        }
    }
    Ok(())
}

fn task_metadata_state_failures(
    repo: &Path,
    check: &Path,
    content: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut task_states = rfc_task_states(&repo.join("docs/rfcs/0010-crucible"))?;
    task_states.extend(rfc_task_states(
        &repo.join("docs/rfcs/0014-signal-driven-fault-model"),
    )?);
    Ok(task_metadata_state_findings(check, content, &task_states))
}

fn task_metadata_state_findings(
    check: &Path,
    content: &str,
    task_states: &BTreeMap<String, bool>,
) -> Vec<String> {
    let mut failures = Vec::new();

    for task in parameter_task_ids(content, "taskIds") {
        if task_states.get(&task) == Some(&false) {
            failures.push(format!(
                "{}: open RFC task `{task}` is listed as completed taskIds evidence",
                check.display()
            ));
        }
    }
    for task in parameter_task_ids(content, "openTaskIds") {
        if task_states.get(&task) == Some(&true) {
            failures.push(format!(
                "{}: completed RFC task `{task}` remains in openTaskIds",
                check.display()
            ));
        }
    }

    failures
}

fn rfc_task_states(dir: &Path) -> Result<BTreeMap<String, bool>, Box<dyn Error>> {
    let mut states = BTreeMap::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("md") {
            continue;
        }
        let content = fs::read_to_string(path)?;
        let mut in_fence = false;
        for line in content.lines() {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence {
                continue;
            }
            let (completed, prefix) = if let Some(rest) = line.strip_prefix("- [x] **") {
                (true, rest)
            } else if let Some(rest) = line.strip_prefix("- [ ] **") {
                (false, rest)
            } else {
                continue;
            };
            let Some((task, _)) = prefix.split_once("**") else {
                continue;
            };
            if task.starts_with("T-") {
                states.insert(task.to_owned(), completed);
            }
        }
    }
    Ok(states)
}

fn parameter_task_ids(content: &str, parameter: &str) -> Vec<String> {
    let marker = format!("{parameter} ? [");
    let Some(start) = content.find(&marker) else {
        return Vec::new();
    };
    let list_start = start + marker.len() - 1;
    let Some(list_end) = matching_list_end(content, list_start) else {
        return Vec::new();
    };
    parse_quoted_task_ids(&content[list_start + 1..list_end])
}

fn parse_quoted_task_ids(content: &str) -> Vec<String> {
    let mut tasks = Vec::new();
    let mut offset = 0;
    while let Some(relative) = content[offset..].find('"') {
        let start = offset + relative;
        let Some((value, after)) = parse_double_quoted(content, start) else {
            break;
        };
        if value.starts_with("T-") {
            tasks.push(value);
        }
        offset = after;
    }
    tasks
}

fn is_repository_path(label: &str) -> bool {
    !label.contains('*')
        && !label.contains(" + ")
        && !label.contains(" and ")
        && label.contains('/')
        && matches!(
            Path::new(label)
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("nix" | "rs" | "toml" | "md" | "patch" | "txt" | "json")
        )
}

fn parse_needles(list: &str) -> Vec<String> {
    let mut needles = Vec::new();
    let mut offset = 0;
    while let Some(relative) = list[offset..].find("needle = ") {
        let value_start = offset + relative + "needle = ".len();
        if let Some((needle, after)) = parse_double_quoted(list, value_start) {
            needles.push(needle);
            offset = after;
        } else if let Some((needle, after)) = parse_indented_string(list, value_start) {
            needles.push(needle);
            offset = after;
        } else {
            offset = value_start + 1;
        }
    }
    needles
}

fn parse_double_quoted(content: &str, start: usize) -> Option<(String, usize)> {
    if content.as_bytes().get(start) != Some(&b'"') {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    for (relative, ch) in content[start + 1..].char_indices() {
        if escaped {
            match ch {
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                '"' => value.push('"'),
                '\\' => value.push('\\'),
                other => {
                    value.push('\\');
                    value.push(other);
                }
            }
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some((value, start + 1 + relative + ch.len_utf8()));
        } else {
            value.push(ch);
        }
    }
    None
}

fn parse_indented_string(content: &str, start: usize) -> Option<(String, usize)> {
    if !content[start..].starts_with("''") {
        return None;
    }
    let body_start = start + 2;
    let relative_end = content[body_start..].find("''")?;
    Some((
        content[body_start..body_start + relative_end].to_string(),
        body_start + relative_end + 2,
    ))
}

fn matching_list_end(content: &str, start: usize) -> Option<usize> {
    let mut depth = 0_u32;
    let mut index = start;
    let bytes = content.as_bytes();
    let mut double_quoted = false;
    let mut indented = false;
    let mut escaped = false;

    while index < bytes.len() {
        if double_quoted {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                double_quoted = false;
            }
            index += 1;
            continue;
        }
        if indented {
            if bytes.get(index) == Some(&b'\'') && bytes.get(index + 1) == Some(&b'\'') {
                indented = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'"' {
            double_quoted = true;
        } else if bytes.get(index) == Some(&b'\'') && bytes.get(index + 1) == Some(&b'\'') {
            indented = true;
            index += 2;
            continue;
        } else if bytes[index] == b'[' {
            depth = depth.saturating_add(1);
        } else if bytes[index] == b']' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

#[test]
fn parser_decodes_literal_and_indented_needles() {
    let source = r#"
      failuresFor "crates/example/src/lib.rs" source [
        {
          label = "literal";
          needle = "line one\nline two";
        }
        {
          label = "indented";
          needle = ''symbol("value")'';
        }
      ]
    "#;
    let list_start = source.find('[').unwrap_or_else(|| panic!("missing list"));
    let list_end =
        matching_list_end(source, list_start).unwrap_or_else(|| panic!("unterminated list"));
    assert_eq!(
        parse_needles(&source[list_start + 1..list_end]),
        ["line one\nline two", "symbol(\"value\")"]
    );
}

#[test]
fn task_metadata_rejects_open_completed_state_inversions() {
    let states = BTreeMap::from([
        (String::from("T-SYNTH-1"), true),
        (String::from("T-SYNTH-2"), false),
    ]);
    let findings = task_metadata_state_findings(
        Path::new("tests/crucible/synthetic.nix"),
        r#"
          taskIds ? ["T-SYNTH-2"],
          openTaskIds ? ["T-SYNTH-1"],
        "#,
        &states,
    );

    assert_eq!(findings.len(), 2);
    assert!(findings[0].contains("open RFC task `T-SYNTH-2`"));
    assert!(findings[1].contains("completed RFC task `T-SYNTH-1`"));
}
