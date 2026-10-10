//! Shared support for `rustdoc_bar_clap`.

pub(super) fn clap_derive_doc_failures(lines: &[&str], display_path: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let mut index = 0usize;

    while index < lines.len() {
        let trimmed = lines[index].trim_start();
        if !trimmed.starts_with("#[") {
            index += 1;
            continue;
        }

        let start = index;
        let mut attribute = String::new();
        while index < lines.len() {
            attribute.push_str(lines[index]);
            if lines[index].contains(']') {
                break;
            }
            index += 1;
        }

        let after_attribute = index.saturating_add(1);
        if clap_derive_attribute(&attribute)
            && (has_outer_doc_comment_before(lines, start)
                || has_outer_doc_comment_after_attributes(lines, after_attribute))
        {
            failures.push(format!(
                "{display_path}:{} clap derive container must not carry `///` docs because they become help text",
                start + 1
            ));
        }

        index += 1;
    }

    failures
}

pub(super) fn clap_derive_attribute(attribute: &str) -> bool {
    attribute.contains("derive")
        && (attribute.contains("Parser")
            || attribute.contains("Subcommand")
            || attribute.contains("Args"))
}

pub(super) fn has_outer_doc_comment_before(lines: &[&str], item_line: usize) -> bool {
    let mut cursor = item_line;

    while cursor > 0 {
        let previous = cursor - 1;
        let trimmed = lines[previous].trim_start();

        if trimmed.is_empty() || is_ordinary_line_comment(trimmed) {
            cursor = previous;
            continue;
        }

        if trimmed.starts_with("///") || trimmed.starts_with("/**") {
            return true;
        }

        if trimmed.starts_with("*/") || trimmed.ends_with("*/") {
            let block = block_comment_before(lines, previous);
            if block.is_outer_doc {
                return true;
            }
            cursor = block.start;
            continue;
        }

        if let Some(attribute_start) = attribute_start_before(lines, cursor) {
            cursor = attribute_start;
            continue;
        }

        return false;
    }

    false
}

pub(super) fn is_ordinary_line_comment(trimmed: &str) -> bool {
    trimmed.starts_with("//") && !trimmed.starts_with("///") && !trimmed.starts_with("//!")
}

pub(super) fn attribute_start_before(lines: &[&str], cursor: usize) -> Option<usize> {
    let mut candidate = cursor.checked_sub(1)?;
    let trimmed = lines[candidate].trim_start();
    if trimmed.starts_with("#[") {
        return Some(candidate);
    }

    if !trimmed.contains(']') {
        return None;
    }

    while candidate > 0 {
        candidate -= 1;
        if lines[candidate].trim_start().starts_with("#[") {
            return Some(candidate);
        }
    }

    None
}

#[derive(Clone, Copy, Debug)]
pub(super) struct BlockComment {
    start: usize,
    is_outer_doc: bool,
}

pub(super) fn block_comment_before(lines: &[&str], end_line: usize) -> BlockComment {
    let mut cursor = end_line;

    loop {
        let trimmed = lines[cursor].trim_start();
        if trimmed.starts_with("/**") {
            return BlockComment {
                start: cursor,
                is_outer_doc: true,
            };
        }
        if trimmed.starts_with("/*") {
            return BlockComment {
                start: cursor,
                is_outer_doc: false,
            };
        }
        if cursor == 0 {
            return BlockComment {
                start: cursor,
                is_outer_doc: false,
            };
        }
        cursor -= 1;
    }
}

pub(super) fn has_outer_doc_comment_after_attributes(lines: &[&str], start_line: usize) -> bool {
    let mut cursor = start_line;

    while cursor < lines.len() {
        let trimmed = lines[cursor].trim_start();

        if trimmed.is_empty() || is_ordinary_line_comment(trimmed) {
            cursor += 1;
            continue;
        }

        if let Some(after_attribute) = attribute_end_after(lines, cursor) {
            cursor = after_attribute;
            continue;
        }

        if trimmed.starts_with("/*") && !trimmed.starts_with("/**") {
            cursor = block_comment_end_after(lines, cursor);
            continue;
        }

        return trimmed.starts_with("///") || trimmed.starts_with("/**");
    }

    false
}

pub(super) fn attribute_end_after(lines: &[&str], start_line: usize) -> Option<usize> {
    if !lines[start_line].trim_start().starts_with("#[") {
        return None;
    }

    for (offset, line) in lines[start_line..].iter().enumerate() {
        if line.contains(']') {
            return Some(start_line + offset + 1);
        }
    }

    Some(lines.len())
}

pub(super) fn block_comment_end_after(lines: &[&str], start_line: usize) -> usize {
    for (offset, line) in lines[start_line..].iter().enumerate() {
        if line.contains("*/") {
            return start_line + offset + 1;
        }
    }

    lines.len()
}
