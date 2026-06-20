//! Shared support for `allow`.

use super::*;

pub(super) fn allow_annotation_failures(path: &Path, content: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let scrubbed = scrub_comments_and_strings(content);
    let scrubbed_lines: Vec<&str> = scrubbed.lines().collect();
    let comment_lines = line_comment_texts(content);

    for index in 0..scrubbed_lines.len() {
        let line_number = index + 1;
        if let Some(comment) = comment_lines.get(index).and_then(Option::as_ref)
            && comment.text.trim_start().starts_with(LINT_ALLOW_PREFIX)
            && lint_allow_rule_from_comment(comment).is_none()
        {
            findings.push(finding(
                path,
                line_number,
                "malformed crucible-lint allow",
                "crucible-lint: allow",
            ));
        }

        for required_rule in allow_attribute_rules_on_line(&scrubbed_lines, index) {
            if !has_lint_allow_in_preceding_marker_block(content, line_number, required_rule) {
                findings.push(finding(path, line_number, "unannotated allow", "#[allow]"));
            }
        }
    }

    findings
}

pub(super) fn has_lint_allow_for_line(content: &str, line: usize, rule: &str) -> bool {
    has_lint_allow_on_previous_line(content, line, rule)
}

pub(super) fn has_lint_allow_on_previous_line(
    content: &str,
    line: usize,
    required_rule: &str,
) -> bool {
    if line <= 1 {
        return false;
    }

    let comment_lines = line_comment_texts(content);
    comment_lines
        .get(line - 2)
        .and_then(Option::as_ref)
        .and_then(lint_allow_rule_from_comment)
        == Some(required_rule)
}

pub(super) fn has_lint_allow_in_preceding_marker_block(
    content: &str,
    line: usize,
    required_rule: &str,
) -> bool {
    if line <= 1 {
        return false;
    }

    let comment_lines = line_comment_texts(content);
    let mut index = line - 2;
    loop {
        let Some(rule) = comment_lines
            .get(index)
            .and_then(Option::as_ref)
            .and_then(lint_allow_rule_from_comment)
        else {
            return false;
        };

        if rule == required_rule {
            return true;
        }

        if index == 0 {
            return false;
        }
        index -= 1;
    }
}

pub(super) fn lint_allow_rule_from_comment(comment: &LineComment) -> Option<&str> {
    if !comment.is_line_leading {
        return None;
    }

    let rest = comment
        .text
        .strip_prefix(' ')?
        .strip_prefix(LINT_ALLOW_PREFIX)?;
    lint_allow_rule_from_rest(rest)
}

pub(super) fn lint_allow_rule_from_rest(rest: &str) -> Option<&str> {
    let (rule, rationale) = rest.split_once(LINT_ALLOW_SEPARATOR)?;
    (LINT_RULES.contains(&rule) && !rationale.trim().is_empty()).then_some(rule)
}

pub(super) fn allow_attribute_rules_on_line(lines: &[&str], start: usize) -> Vec<&'static str> {
    let Some(first_line) = lines.get(start) else {
        return Vec::new();
    };
    if !first_line.contains('#') {
        return Vec::new();
    }

    let mut rules = Vec::new();
    let mut cursor = 0usize;
    while let Some(attribute_start) = next_attribute_start(lines[start], cursor) {
        if let Some(attribute) = attribute_text(lines, start, attribute_start) {
            for rule in allow_attribute_rules(&attribute.normalized) {
                push_unique_rule(&mut rules, rule);
            }

            if attribute.end_line != start {
                break;
            }
            cursor = attribute.end_column;
        } else {
            cursor = attribute_start + 1;
        }
    }

    rules
}

pub(super) fn next_attribute_start(line: &str, cursor: usize) -> Option<usize> {
    line.get(cursor..)
        .and_then(|rest| rest.find('#').map(|relative| cursor + relative))
}

pub(super) fn attribute_text(
    lines: &[&str],
    start: usize,
    start_column: usize,
) -> Option<AttributeText> {
    let mut normalized = String::new();
    let mut bracket_depth = 0usize;
    let mut saw_attribute = false;

    for (line_offset, line) in lines[start..].iter().enumerate() {
        let line_start = if line_offset == 0 { start_column } else { 0 };
        for (byte_offset, ch) in line[line_start..].char_indices() {
            if !ch.is_whitespace() {
                normalized.push(ch);
            }

            match ch {
                '[' => {
                    saw_attribute = true;
                    bracket_depth += 1;
                }
                ']' if saw_attribute => {
                    bracket_depth = bracket_depth.saturating_sub(1);
                    if bracket_depth == 0 {
                        return Some(AttributeText {
                            normalized,
                            end_line: start + line_offset,
                            end_column: line_start + byte_offset + ch.len_utf8(),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    None
}

pub(super) fn allow_attribute_rules(normalized: &str) -> Vec<&'static str> {
    let is_direct_allow = normalized.starts_with("#[allow(") || normalized.starts_with("#![allow(");
    let is_cfg_attr =
        normalized.starts_with("#[cfg_attr(") || normalized.starts_with("#![cfg_attr(");

    if !(is_direct_allow || is_cfg_attr && normalized.contains("allow(")) {
        return Vec::new();
    }

    let mut rules = Vec::new();
    for allow_group in allow_group_texts(normalized) {
        for lint in allow_group
            .split(',')
            .map(str::trim)
            .filter(|lint| !lint.is_empty())
        {
            let rule = match lint {
                "clippy::disallowed_types" => "clippy-disallowed-type",
                "clippy::disallowed_methods" => "clippy-disallowed-method",
                "clippy::unwrap_used" | "clippy::expect_used" => "panic-shortcut",
                _ => "rust-allow",
            };
            push_unique_rule(&mut rules, rule);
        }
    }
    rules
}

pub(super) fn allow_group_texts(normalized: &str) -> Vec<&str> {
    let mut groups = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = normalized[cursor..].find("allow(") {
        let open_paren = cursor + relative + "allow".len();
        if let Some(close_paren) = closing_paren(normalized, open_paren) {
            groups.push(&normalized[open_paren + 1..close_paren]);
            cursor = close_paren + 1;
        } else {
            break;
        }
    }
    groups
}

pub(super) fn closing_paren(value: &str, open_paren: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (byte_index, ch) in value[open_paren..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open_paren + byte_index);
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn push_unique_rule<'a>(rules: &mut Vec<&'a str>, rule: &'a str) {
    if !rules.contains(&rule) {
        rules.push(rule);
    }
}
