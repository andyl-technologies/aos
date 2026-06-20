//! Shared support for `rustdoc_bar_docs`.

use super::*;

pub(super) fn module_doc_lines(source: &str) -> Vec<String> {
    let mut docs = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(doc) = trimmed.strip_prefix("//!") {
            docs.push(doc.trim_start().to_string());
            continue;
        }

        break;
    }

    docs
}

pub(super) fn has_tagged_format_sketch(module_docs: &[String]) -> bool {
    module_docs.iter().any(|line| {
        ["```text", "```toml", "```ignore", "```no_run"]
            .iter()
            .any(|fence| line.trim_start().starts_with(fence))
    })
}

pub(super) fn ascii_comment_doc_failures(lines: &[&str], display_path: &str) -> Vec<String> {
    let mut failures = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if is_comment_or_doc(trimmed) && !trimmed.is_ascii() {
            failures.push(format!(
                "{display_path}:{} contains non-ASCII comment/doc text",
                index + 1
            ));
        }
    }

    failures
}

pub(super) fn is_comment_or_doc(trimmed: &str) -> bool {
    trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
}

pub(super) fn rustdoc_fence_failures(lines: &[&str], display_path: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let mut open_fence: Option<RustdocFence> = None;

    for (line_number, doc) in rustdoc_text_lines(lines) {
        let doc = doc.trim_start();
        let Some(fence) = rustdoc_fence_line(doc) else {
            continue;
        };

        if let Some(open) = open_fence {
            if fence.backticks < open.backticks {
                continue;
            }

            if fence.info.is_empty() {
                open_fence = None;
                continue;
            }

            failures.push(format!(
                "{display_path}:{line_number} rustdoc fence closer for fence opened at line {} must not carry an info string",
                open.line
            ));
            continue;
        }

        let info = fence.info;
        if info.is_empty() {
            failures.push(format!(
                "{display_path}:{line_number} has an untagged rustdoc fence"
            ));
        } else {
            let tag = rustdoc_fence_tag(info);
            if !RUSTDOC_FENCE_TAGS.contains(&tag) {
                failures.push(format!(
                    "{display_path}:{line_number} has unsupported rustdoc fence tag `{tag}`"
                ));
            }

            if rustdoc_fence_is_doctested(tag) && !package_is_doctested(display_path) {
                failures.push(format!(
                    "{display_path}:{line_number} has a doctested rustdoc fence that is not covered by `cargo test --doc`"
                ));
            }
        }

        open_fence = Some(RustdocFence {
            line: line_number,
            backticks: fence.backticks,
        });
    }

    if let Some(fence) = open_fence {
        failures.push(format!(
            "{display_path}:{} opens an unterminated rustdoc fence",
            fence.line
        ));
    }

    failures
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RustdocFence {
    line: usize,
    backticks: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RustdocFenceLine<'a> {
    backticks: usize,
    info: &'a str,
}

pub(super) fn rustdoc_fence_line(doc: &str) -> Option<RustdocFenceLine<'_>> {
    let backticks = doc
        .chars()
        .take_while(|character| *character == '`')
        .count();
    if backticks < 3 {
        return None;
    }

    Some(RustdocFenceLine {
        backticks,
        info: doc.get(backticks..).unwrap_or("").trim(),
    })
}

pub(super) fn rustdoc_text_lines(lines: &[&str]) -> Vec<(usize, String)> {
    let mut docs = Vec::new();
    let mut inside_block = false;

    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim_start();

        if inside_block {
            let (text, still_inside_block) = block_rustdoc_line_text(trimmed);
            docs.push((line_number, text.to_string()));
            inside_block = still_inside_block;
            continue;
        }

        if let Some(doc) = rustdoc_line_text(trimmed) {
            docs.push((line_number, doc.to_string()));
            continue;
        }

        if let Some((text, still_inside_block)) = block_rustdoc_start_text(trimmed) {
            docs.push((line_number, text.to_string()));
            inside_block = still_inside_block;
        }
    }

    docs
}

pub(super) fn rustdoc_line_text(trimmed: &str) -> Option<&str> {
    trimmed
        .strip_prefix("//!")
        .or_else(|| trimmed.strip_prefix("///"))
}

pub(super) fn block_rustdoc_start_text(trimmed: &str) -> Option<(&str, bool)> {
    let text = trimmed
        .strip_prefix("/*!")
        .or_else(|| trimmed.strip_prefix("/**"))?;
    Some(block_rustdoc_text(text))
}

pub(super) fn block_rustdoc_line_text(trimmed: &str) -> (&str, bool) {
    block_rustdoc_text(trimmed)
}

pub(super) fn block_rustdoc_text(text: &str) -> (&str, bool) {
    let (text, closed) = match text.split_once("*/") {
        Some((before_close, _after_close)) => (before_close, true),
        None => (text, false),
    };

    (trim_block_rustdoc_margin(text), !closed)
}

pub(super) fn trim_block_rustdoc_margin(text: &str) -> &str {
    let text = text.trim_start();
    match text.strip_prefix('*') {
        Some(after_star) => after_star.strip_prefix(' ').unwrap_or(after_star),
        None => text,
    }
}

pub(super) fn rustdoc_fence_tag(info: &str) -> &str {
    info.split(|character: char| character == ',' || character.is_ascii_whitespace())
        .next()
        .unwrap_or("")
}

pub(super) fn rustdoc_fence_is_doctested(tag: &str) -> bool {
    DOCTESTED_RUSTDOC_FENCE_TAGS.contains(&tag)
}

pub(super) fn package_is_doctested(display_path: &str) -> bool {
    let Some(package) = display_path.split('/').next() else {
        return true;
    };
    !NON_DOCTESTED_PACKAGES.contains(&package)
}
