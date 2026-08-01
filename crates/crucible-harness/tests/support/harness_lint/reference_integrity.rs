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
    let mut failures = Vec::new();
    let mut in_stop_path = false;
    let mut brace_depth = 0_i64;

    for (index, line) in content.lines().enumerate() {
        if line.contains("fn enter_stopped(") {
            in_stop_path = true;
        }
        if line.contains("Outcome::") && !in_stop_path {
            failures.push(format!(
                "line {} constructs a terminal Outcome outside enter_stopped",
                index + 1
            ));
        }
        if in_stop_path {
            brace_depth += line.matches('{').count() as i64;
            brace_depth -= line.matches('}').count() as i64;
            if brace_depth == 0 && line.contains('}') {
                in_stop_path = false;
            }
        }
    }
    failures
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
    let task_states = rfc_task_states(&repo.join("docs/rfcs/0010-crucible"))?;
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
