//! Classifies Rust source lines as implementation or test responsibilities.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SourceRoleLineCounts {
    pub(super) implementation: usize,
    pub(super) tests: usize,
}

pub(super) fn source_role_line_counts(
    package_dir: &Path,
    source: &Path,
    content: &str,
) -> SourceRoleLineCounts {
    let total = content.lines().count();
    if is_test_only_source(package_dir, source) || is_test_support_only_source(content) {
        return SourceRoleLineCounts {
            implementation: 0,
            tests: total,
        };
    }

    let test_ranges = cfg_test_line_ranges(content);
    let tests = (1..=total)
        .filter(|line| line_in_ranges(*line, &test_ranges))
        .count();

    SourceRoleLineCounts {
        implementation: total - tests,
        tests,
    }
}

pub(super) fn is_test_only_source(package_dir: &Path, source: &Path) -> bool {
    source.strip_prefix(package_dir).is_ok_and(|relative| {
        relative.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some("tests" | "test_support")
            )
        }) || relative.file_name().is_some_and(|name| {
            name == "tests.rs"
                || name == "test_support.rs"
                || name.to_str().is_some_and(|name| {
                    name.ends_with("_test.rs")
                        || name.ends_with("_tests.rs")
                        || name.contains("_test_")
                })
        })
    })
}

pub(super) fn is_test_support_only_source(content: &str) -> bool {
    let scrubbed = scrub_source_comments_and_literals(content);

    for (source_line, scrubbed_line) in content.lines().zip(scrubbed.lines()) {
        let trimmed = scrubbed_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.starts_with("#![") {
            return false;
        }

        let normalized = source_line
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>();
        if matches!(
            normalized.as_str(),
            "#![cfg(test)]" | "#![cfg(any(test,feature=\"test-support\"))]"
        ) {
            return true;
        }
    }

    false
}

pub(super) fn cfg_test_line_ranges(content: &str) -> Vec<std::ops::RangeInclusive<usize>> {
    let scrubbed = scrub_source_comments_and_literals(content);
    let lines = scrubbed.lines().collect::<Vec<_>>();
    let mut ranges = Vec::new();

    for index in 0..lines.len() {
        if !line_is_cfg_test(lines[index]) {
            continue;
        }

        if let Some(range) = cfg_item_line_range_after(&lines, index) {
            ranges.push(range);
        }
    }

    ranges
}

pub(super) fn line_in_ranges(line: usize, ranges: &[std::ops::RangeInclusive<usize>]) -> bool {
    ranges.iter().any(|range| range.contains(&line))
}

fn line_is_cfg_test(line: &str) -> bool {
    let normalized = line
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    normalized == "#[cfg(test)]"
        || normalized
            .strip_prefix("#[cfg(all(")
            .and_then(|cfg| cfg.strip_suffix("))]"))
            .is_some_and(|cfg| cfg.split(',').any(|predicate| predicate == "test"))
}

fn cfg_item_line_range_after(
    lines: &[&str],
    attribute_index: usize,
) -> Option<std::ops::RangeInclusive<usize>> {
    let item_index = first_item_line_after_attributes(lines, attribute_index + 1)?;
    let mut parentheses = 0usize;
    let mut brackets = 0usize;
    let mut braces = 0usize;
    let mut saw_braced_body = false;

    for (index, line) in lines.iter().enumerate().skip(item_index) {
        for (column, ch) in line.char_indices() {
            match ch {
                '(' => parentheses += 1,
                ')' if parentheses > 0 => parentheses -= 1,
                '[' => brackets += 1,
                ']' if brackets > 0 => brackets -= 1,
                '{' => {
                    braces += 1;
                    saw_braced_body = true;
                }
                '}' if braces > 0 => {
                    braces -= 1;
                    let trailing = line[column + ch.len_utf8()..].trim();
                    let closes_item = trailing.is_empty() || matches!(trailing, ";" | ",");
                    if saw_braced_body
                        && parentheses == 0
                        && brackets == 0
                        && braces == 0
                        && closes_item
                    {
                        return Some(attribute_index + 1..=index + 1);
                    }
                }
                ';' if parentheses == 0 && brackets == 0 && braces == 0 => {
                    return Some(attribute_index + 1..=index + 1);
                }
                ',' if parentheses == 0
                    && brackets == 0
                    && braces == 0
                    && line[column + ch.len_utf8()..].trim().is_empty() =>
                {
                    return Some(attribute_index + 1..=index + 1);
                }
                _ => {}
            }
        }
    }

    None
}

fn first_item_line_after_attributes(lines: &[&str], start: usize) -> Option<usize> {
    let mut attribute_brackets = 0usize;

    for (index, line) in lines.iter().enumerate().skip(start) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if attribute_brackets > 0 || trimmed.starts_with("#[") {
            for ch in line.chars() {
                match ch {
                    '[' => attribute_brackets += 1,
                    ']' if attribute_brackets > 0 => attribute_brackets -= 1,
                    _ => {}
                }
            }
            continue;
        }

        return Some(index);
    }

    None
}

fn scrub_source_comments_and_literals(content: &str) -> String {
    let chars = content.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(content.len());
    let mut index = 0usize;
    let mut state = SourceScannerState::Code;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();

        match state {
            SourceScannerState::Code => {
                if ch == '/' && next == Some('/') {
                    output.push_str("  ");
                    index += 2;
                    state = SourceScannerState::LineComment;
                } else if ch == '/' && next == Some('*') {
                    output.push_str("  ");
                    index += 2;
                    state = SourceScannerState::BlockComment { depth: 1 };
                } else if ch == '"' {
                    output.push(' ');
                    index += 1;
                    state = SourceScannerState::String;
                } else if let Some(end) = source_char_literal_end(&chars, index) {
                    replace_source_range_with_spaces(&chars, index, end, &mut output);
                    index = end;
                } else if let Some(end) = source_raw_string_end(&chars, index) {
                    replace_source_range_with_spaces(&chars, index, end, &mut output);
                    index = end;
                } else {
                    output.push(ch);
                    index += 1;
                }
            }
            SourceScannerState::LineComment => {
                if ch == '\n' {
                    output.push('\n');
                    state = SourceScannerState::Code;
                } else {
                    output.push(' ');
                }
                index += 1;
            }
            SourceScannerState::BlockComment { depth } => {
                if ch == '/' && next == Some('*') {
                    output.push_str("  ");
                    index += 2;
                    state = SourceScannerState::BlockComment { depth: depth + 1 };
                } else if ch == '*' && next == Some('/') {
                    output.push_str("  ");
                    index += 2;
                    state = if depth == 1 {
                        SourceScannerState::Code
                    } else {
                        SourceScannerState::BlockComment { depth: depth - 1 }
                    };
                } else {
                    output.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
            SourceScannerState::String => {
                if ch == '\\' && next.is_some() {
                    output.push(' ');
                    output.push(if next == Some('\n') { '\n' } else { ' ' });
                    index += 2;
                } else if ch == '"' {
                    output.push(' ');
                    index += 1;
                    state = SourceScannerState::Code;
                } else {
                    output.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
        }
    }

    output
}

fn source_raw_string_end(chars: &[char], start: usize) -> Option<usize> {
    let raw_prefix = if chars.get(start) == Some(&'r') {
        1
    } else if chars.get(start) == Some(&'b') && chars.get(start + 1) == Some(&'r') {
        2
    } else {
        return None;
    };
    let mut cursor = start + raw_prefix;
    let mut hashes = 0usize;

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
            let end = cursor + 1 + hashes;
            if end <= chars.len() && chars[cursor + 1..end].iter().all(|ch| *ch == '#') {
                return Some(end);
            }
        }
        cursor += 1;
    }

    Some(chars.len())
}

fn source_char_literal_end(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start) != Some(&'\'') {
        return None;
    }

    let mut cursor = start + 1;
    if chars.get(cursor) == Some(&'\\') {
        cursor += 2;
    } else {
        cursor += 1;
    }

    (chars.get(cursor) == Some(&'\'')).then_some(cursor + 1)
}

fn replace_source_range_with_spaces(chars: &[char], start: usize, end: usize, output: &mut String) {
    for ch in &chars[start..end] {
        output.push(if *ch == '\n' { '\n' } else { ' ' });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceScannerState {
    Code,
    LineComment,
    BlockComment { depth: usize },
    String,
}
