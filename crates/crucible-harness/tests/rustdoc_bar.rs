//! Checks the RFC-0010 rustdoc standard for Crucible crates.
//!
//! Rustdoc's own lints enforce missing public docs and broken intra-doc links.
//! This harness lint covers the source-shape rules that rustdoc does not model:
//! module headers, crate-root module maps, format sketches for format-owning
//! modules, tagged rustdoc fences, clap derive help text boundaries, ASCII
//! comments/docs, and `# Errors`/`# Panics` sections.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crucible_harness::spec_index::crate_spec_index;

const FORMAT_OWNING_SOURCES: &[(&str, &str)] = &[
    ("crucible-shmem/src/lib.rs", "shared-memory ABI"),
    ("crucible-protocol/src/lib.rs", "wire protocol"),
    ("crucible-harness/src/abi.rs", "ABI golden-vector records"),
];
const RUSTDOC_FENCE_TAGS: &[&str] = &["text", "rust", "toml", "no_run", "ignore"];
const DOCTESTED_RUSTDOC_FENCE_TAGS: &[&str] = &["rust", "no_run"];
const NON_DOCTESTED_PACKAGES: &[&str] = &["crucible-cli", "crucible-qemu-plugin"];

#[test]
fn crucible_workspace_sources_meet_rustdoc_bar() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let crates_dir = root.join("crates");
    let mut failures = Vec::new();

    assert_expected_crucible_package_set(&crates_dir, &mut failures)?;

    for spec in crate_spec_index() {
        let package_dir = crates_dir.join(spec.package);
        let root_path = package_dir.join(spec.root);
        let source_files = rust_source_files(&package_dir.join("src"))?;

        for source_path in source_files {
            let display_path = display_repo_path(&source_path);
            let source = fs::read_to_string(&source_path)?;
            let is_crate_root = source_path == root_path;
            let format_owner = format_owner_for(&display_path);

            failures.extend(rustdoc_bar_failures(
                &source,
                &display_path,
                is_crate_root,
                format_owner,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Crucible rustdoc-bar lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn rustdoc_bar_rules_reject_missing_sections_and_shape_drift() {
    let missing_module_doc = r#"
pub fn documented() {}
"#;
    let missing_module_map = r#"
//! synthetic crate

/// A documented function.
pub fn documented() {}
"#;
    let missing_format_block = r#"
//! synthetic format module
//!
//! Module map: synthetic.

/// A documented function.
pub fn documented() {}
"#;
    let missing_errors = r#"
//! synthetic module

/// A fallible function.
pub fn fallible() -> Result<(), ()> {
    Ok(())
}
"#;
    let missing_panics = r#"
//! synthetic module

/// A panicking function.
pub fn panics() {
    panic!("boom");
}
"#;
    let non_ascii_comment = r#"
//! synthetic module

// smart quote: “
/// A documented function.
pub fn documented() {}
"#;
    let untagged_fence = r#"
//! synthetic module
//!
//! ```
//! format example
//! ```

/// A documented function.
pub fn documented() {}
"#;
    let unsupported_fence = r#"
//! synthetic module
//!
//! ```console
//! command output
//! ```

/// A documented function.
pub fn documented() {}
"#;
    let malformed_closing_fence = r#"
//! synthetic module
//!
//! ```text
//! format example
//! ```rust
//! ```

/// A documented function.
pub fn documented() {}
"#;
    let nested_shorter_fence = r#"
//! synthetic module
//!
//! ````text
//! ```rust
//! let value = 1;
//! ```
//! ````

/// A documented function.
pub fn documented() {}
"#;
    let untagged_block_fence = r#"
/*!
 * synthetic module
 *
 * ```
 * format example
 * ```
 */

/// A documented function.
pub fn documented() {}
"#;
    let non_doctested_rust_fence = r#"
//! synthetic binary
//!
//! ```rust
//! let value = 1;
//! ```

/// A documented function.
pub fn documented() {}
"#;
    let non_doctested_no_run_fence = r#"
//! synthetic binary
//!
//! ```no_run
//! let value = 1;
//! ```

/// A documented function.
pub fn documented() {}
"#;
    let documented_clap_container = r#"
//! synthetic CLI

/// A parser container that should not become help text.
#[derive(Parser)]
struct Cli {}
"#;
    let documented_clap_container_before_comment = r#"
//! synthetic CLI

/// A parser container that should not become help text.
// kept for the CLI parser item
#[derive(Parser)]
struct Cli {}
"#;
    let documented_clap_container_after_derive = r#"
//! synthetic CLI

#[derive(Parser)]
/// A parser container that should not become help text.
struct Cli {}
"#;
    let documented_clap_container_after_comment = r#"
//! synthetic CLI

#[derive(Parser)]
// kept for the CLI parser item
/// A parser container that should not become help text.
struct Cli {}
"#;
    let documented_cfg_attr_clap_container = r#"
//! synthetic CLI

/// A parser container that should not become help text.
#[cfg_attr(feature = "cli", derive(Parser))]
struct Cli {}
"#;
    let documented_clap_container_before_multiline_attr = r#"
//! synthetic CLI

/// A parser container that should not become help text.
#[cfg_attr(
    feature = "cli",
    allow(dead_code)
)]
#[derive(Parser)]
struct Cli {}
"#;
    let documented_clap_container_after_multiline_attr = r#"
//! synthetic CLI

#[derive(Parser)]
#[cfg_attr(
    feature = "cli",
    allow(dead_code)
)]
/// A parser container that should not become help text.
struct Cli {}
"#;
    let documented_cfg_attr_clap_container_after_attr = r#"
//! synthetic CLI

#[cfg_attr(feature = "cli", derive(Parser))]
/// A parser container that should not become help text.
struct Cli {}
"#;

    assert_contains(
        &rustdoc_bar_failures(missing_module_doc, "synthetic.rs", false, None),
        "missing module-level `//!`",
    );
    assert_contains(
        &rustdoc_bar_failures(missing_module_map, "synthetic.rs", true, None),
        "missing crate-root `Module map:`",
    );
    assert_contains(
        &rustdoc_bar_failures(
            missing_format_block,
            "synthetic.rs",
            true,
            Some("synthetic format"),
        ),
        "missing tagged format sketch",
    );
    assert_contains(
        &rustdoc_bar_failures(missing_errors, "synthetic.rs", false, None),
        "missing `# Errors`",
    );
    assert_contains(
        &rustdoc_bar_failures(missing_panics, "synthetic.rs", false, None),
        "missing `# Panics`",
    );
    assert_contains(
        &rustdoc_bar_failures(non_ascii_comment, "synthetic.rs", false, None),
        "contains non-ASCII comment/doc text",
    );
    assert_contains(
        &rustdoc_bar_failures(untagged_fence, "synthetic.rs", false, None),
        "untagged rustdoc fence",
    );
    assert_contains(
        &rustdoc_bar_failures(unsupported_fence, "synthetic.rs", false, None),
        "unsupported rustdoc fence tag",
    );
    assert_contains(
        &rustdoc_bar_failures(malformed_closing_fence, "synthetic.rs", false, None),
        "rustdoc fence closer",
    );
    assert_not_contains(
        &rustdoc_bar_failures(nested_shorter_fence, "synthetic.rs", false, None),
        "rustdoc fence closer",
    );
    assert_contains(
        &rustdoc_bar_failures(untagged_block_fence, "synthetic.rs", false, None),
        "untagged rustdoc fence",
    );
    assert_contains(
        &rustdoc_bar_failures(
            non_doctested_rust_fence,
            "crucible-cli/src/main.rs",
            true,
            None,
        ),
        "is not covered by `cargo test --doc`",
    );
    assert_contains(
        &rustdoc_bar_failures(
            non_doctested_no_run_fence,
            "crucible-cli/src/main.rs",
            true,
            None,
        ),
        "is not covered by `cargo test --doc`",
    );
    assert_contains(
        &rustdoc_bar_failures(
            documented_clap_container,
            "crucible-cli/src/main.rs",
            false,
            None,
        ),
        "clap derive container must not carry `///` docs",
    );
    assert_contains(
        &rustdoc_bar_failures(
            documented_clap_container_before_comment,
            "crucible-cli/src/main.rs",
            false,
            None,
        ),
        "clap derive container must not carry `///` docs",
    );
    assert_contains(
        &rustdoc_bar_failures(
            documented_clap_container_after_derive,
            "crucible-cli/src/main.rs",
            false,
            None,
        ),
        "clap derive container must not carry `///` docs",
    );
    assert_contains(
        &rustdoc_bar_failures(
            documented_clap_container_after_comment,
            "crucible-cli/src/main.rs",
            false,
            None,
        ),
        "clap derive container must not carry `///` docs",
    );
    assert_contains(
        &rustdoc_bar_failures(
            documented_cfg_attr_clap_container,
            "crucible-cli/src/main.rs",
            false,
            None,
        ),
        "clap derive container must not carry `///` docs",
    );
    assert_contains(
        &rustdoc_bar_failures(
            documented_clap_container_before_multiline_attr,
            "crucible-cli/src/main.rs",
            false,
            None,
        ),
        "clap derive container must not carry `///` docs",
    );
    assert_contains(
        &rustdoc_bar_failures(
            documented_clap_container_after_multiline_attr,
            "crucible-cli/src/main.rs",
            false,
            None,
        ),
        "clap derive container must not carry `///` docs",
    );
    assert_contains(
        &rustdoc_bar_failures(
            documented_cfg_attr_clap_container_after_attr,
            "crucible-cli/src/main.rs",
            false,
            None,
        ),
        "clap derive container must not carry `///` docs",
    );
}

fn rustdoc_bar_failures(
    source: &str,
    display_path: &str,
    is_crate_root: bool,
    format_owner: Option<&str>,
) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut failures = Vec::new();

    let module_docs = module_doc_lines(source);
    if module_docs.is_empty() {
        failures.push(format!(
            "{display_path}: missing module-level `//!` rustdoc header"
        ));
    }

    if is_crate_root && !module_docs.iter().any(|line| line.contains("Module map:")) {
        failures.push(format!(
            "{display_path}: missing crate-root `Module map:` in `//!` overview"
        ));
    }

    if let Some(owner) = format_owner
        && !has_tagged_format_sketch(&module_docs)
    {
        failures.push(format!(
            "{display_path}: {owner} module is missing tagged format sketch"
        ));
    }

    failures.extend(ascii_comment_doc_failures(&lines, display_path));
    failures.extend(rustdoc_fence_failures(&lines, display_path));
    failures.extend(clap_derive_doc_failures(&lines, display_path));
    failures.extend(public_result_doc_failures(&lines, display_path));
    failures.extend(public_panic_doc_failures(&lines, display_path));

    failures
}

fn module_doc_lines(source: &str) -> Vec<String> {
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

fn has_tagged_format_sketch(module_docs: &[String]) -> bool {
    module_docs.iter().any(|line| {
        ["```text", "```toml", "```ignore", "```no_run"]
            .iter()
            .any(|fence| line.trim_start().starts_with(fence))
    })
}

fn ascii_comment_doc_failures(lines: &[&str], display_path: &str) -> Vec<String> {
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

fn is_comment_or_doc(trimmed: &str) -> bool {
    trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
}

fn rustdoc_fence_failures(lines: &[&str], display_path: &str) -> Vec<String> {
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
struct RustdocFence {
    line: usize,
    backticks: usize,
}

#[derive(Clone, Copy, Debug)]
struct RustdocFenceLine<'a> {
    backticks: usize,
    info: &'a str,
}

fn rustdoc_fence_line(doc: &str) -> Option<RustdocFenceLine<'_>> {
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

fn rustdoc_text_lines(lines: &[&str]) -> Vec<(usize, String)> {
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

fn rustdoc_line_text(trimmed: &str) -> Option<&str> {
    trimmed
        .strip_prefix("//!")
        .or_else(|| trimmed.strip_prefix("///"))
}

fn block_rustdoc_start_text(trimmed: &str) -> Option<(&str, bool)> {
    let text = trimmed
        .strip_prefix("/*!")
        .or_else(|| trimmed.strip_prefix("/**"))?;
    Some(block_rustdoc_text(text))
}

fn block_rustdoc_line_text(trimmed: &str) -> (&str, bool) {
    block_rustdoc_text(trimmed)
}

fn block_rustdoc_text(text: &str) -> (&str, bool) {
    let (text, closed) = match text.split_once("*/") {
        Some((before_close, _after_close)) => (before_close, true),
        None => (text, false),
    };

    (trim_block_rustdoc_margin(text), !closed)
}

fn trim_block_rustdoc_margin(text: &str) -> &str {
    let text = text.trim_start();
    match text.strip_prefix('*') {
        Some(after_star) => after_star.strip_prefix(' ').unwrap_or(after_star),
        None => text,
    }
}

fn rustdoc_fence_tag(info: &str) -> &str {
    info.split(|character: char| character == ',' || character.is_ascii_whitespace())
        .next()
        .unwrap_or("")
}

fn rustdoc_fence_is_doctested(tag: &str) -> bool {
    DOCTESTED_RUSTDOC_FENCE_TAGS.contains(&tag)
}

fn package_is_doctested(display_path: &str) -> bool {
    let Some(package) = display_path.split('/').next() else {
        return true;
    };
    !NON_DOCTESTED_PACKAGES.contains(&package)
}

fn clap_derive_doc_failures(lines: &[&str], display_path: &str) -> Vec<String> {
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

fn clap_derive_attribute(attribute: &str) -> bool {
    attribute.contains("derive")
        && (attribute.contains("Parser")
            || attribute.contains("Subcommand")
            || attribute.contains("Args"))
}

fn has_outer_doc_comment_before(lines: &[&str], item_line: usize) -> bool {
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

fn is_ordinary_line_comment(trimmed: &str) -> bool {
    trimmed.starts_with("//") && !trimmed.starts_with("///") && !trimmed.starts_with("//!")
}

fn attribute_start_before(lines: &[&str], cursor: usize) -> Option<usize> {
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
struct BlockComment {
    start: usize,
    is_outer_doc: bool,
}

fn block_comment_before(lines: &[&str], end_line: usize) -> BlockComment {
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

fn has_outer_doc_comment_after_attributes(lines: &[&str], start_line: usize) -> bool {
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

fn attribute_end_after(lines: &[&str], start_line: usize) -> Option<usize> {
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

fn block_comment_end_after(lines: &[&str], start_line: usize) -> usize {
    for (offset, line) in lines[start_line..].iter().enumerate() {
        if line.contains("*/") {
            return start_line + offset + 1;
        }
    }

    lines.len()
}

fn public_result_doc_failures(lines: &[&str], display_path: &str) -> Vec<String> {
    public_functions(lines)
        .into_iter()
        .filter(|function| signature_returns_result(&function.signature))
        .filter(|function| !doc_block_contains(lines, function.line, "# Errors"))
        .map(|function| {
            format!(
                "{display_path}:{} public Result-returning function `{}` is missing `# Errors`",
                function.line + 1,
                function.name
            )
        })
        .collect()
}

fn public_panic_doc_failures(lines: &[&str], display_path: &str) -> Vec<String> {
    public_functions(lines)
        .into_iter()
        .filter(|function| function.body_contains_panic)
        .filter(|function| !doc_block_contains(lines, function.line, "# Panics"))
        .map(|function| {
            format!(
                "{display_path}:{} public panicking function `{}` is missing `# Panics`",
                function.line + 1,
                function.name
            )
        })
        .collect()
}

#[derive(Clone, Debug)]
struct FunctionContext {
    line: usize,
    name: String,
    signature: String,
    body_contains_panic: bool,
}

fn public_functions(lines: &[&str]) -> Vec<FunctionContext> {
    let mut functions = Vec::new();
    let mut brace_depth = 0usize;
    let mut public_trait_depth = None;

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();

        if matches!(public_trait_depth, Some(depth) if brace_depth < depth) {
            public_trait_depth = None;
        }

        let inside_public_trait = public_trait_depth.is_some();
        if is_public_function_start(trimmed) || (inside_public_trait && trimmed.starts_with("fn "))
        {
            let signature = collect_signature(lines, index);
            functions.push(FunctionContext {
                line: index,
                name: function_name(&signature),
                body_contains_panic: signature.contains('{') && body_contains_panic(lines, index),
                signature,
            });
        }

        if trimmed.starts_with("pub trait ") && line.contains('{') {
            public_trait_depth = Some(brace_depth + opening_braces(line));
        }

        brace_depth = brace_depth
            .saturating_add(opening_braces(line))
            .saturating_sub(closing_braces(line));
    }

    functions
}

fn is_public_function_start(trimmed: &str) -> bool {
    trimmed.starts_with("pub fn ")
        || trimmed.starts_with("pub async fn ")
        || trimmed.starts_with("pub const fn ")
        || trimmed.starts_with("pub(crate) fn ")
        || trimmed.starts_with("pub(crate) async fn ")
        || trimmed.starts_with("pub(crate) const fn ")
}

fn collect_signature(lines: &[&str], start: usize) -> String {
    let mut signature = String::new();

    for line in &lines[start..] {
        let trimmed = line.trim();
        if !signature.is_empty() {
            signature.push(' ');
        }
        signature.push_str(trimmed);

        if trimmed.contains('{') || trimmed.ends_with(';') {
            break;
        }
    }

    signature
}

fn signature_returns_result(signature: &str) -> bool {
    signature.contains("->") && signature.contains("Result")
}

fn function_name(signature: &str) -> String {
    let after_fn = signature
        .split_once("fn ")
        .map(|(_before, after)| after)
        .unwrap_or(signature);
    after_fn
        .split(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
        .next()
        .unwrap_or("<unknown>")
        .to_string()
}

fn body_contains_panic(lines: &[&str], start: usize) -> bool {
    let mut depth = 0usize;
    let mut started = false;

    for line in &lines[start..] {
        if line.contains("panic!")
            || line.contains("assert!")
            || line.contains("todo!")
            || line.contains("unimplemented!")
        {
            return true;
        }

        let opens = opening_braces(line);
        let closes = closing_braces(line);
        if opens > 0 {
            started = true;
        }
        depth = depth.saturating_add(opens).saturating_sub(closes);

        if started && depth == 0 {
            break;
        }
    }

    false
}

fn opening_braces(line: &str) -> usize {
    line.chars().filter(|character| *character == '{').count()
}

fn closing_braces(line: &str) -> usize {
    line.chars().filter(|character| *character == '}').count()
}

fn doc_block_contains(lines: &[&str], item_line: usize, required: &str) -> bool {
    doc_block_before(lines, item_line)
        .iter()
        .any(|line| line.trim() == required)
}

fn doc_block_before(lines: &[&str], item_line: usize) -> Vec<String> {
    let mut docs = Vec::new();
    let mut cursor = item_line;

    while cursor > 0 {
        cursor -= 1;
        let trimmed = lines[cursor].trim_start();

        if trimmed.is_empty() || trimmed.starts_with("#[") {
            continue;
        }

        if let Some(doc) = trimmed.strip_prefix("///") {
            docs.push(doc.trim_start().to_string());
            continue;
        }

        break;
    }

    docs.reverse();
    docs
}

fn format_owner_for(display_path: &str) -> Option<&'static str> {
    FORMAT_OWNING_SOURCES
        .iter()
        .find_map(|(path, owner)| (*path == display_path).then_some(*owner))
}

fn rust_source_files(src_dir: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let mut files = Vec::new();
    collect_rust_source_files(src_dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_rust_source_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), io::Error> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_source_files(&path, files)?;
            continue;
        }

        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }

    Ok(())
}

fn assert_expected_crucible_package_set(
    crates_dir: &Path,
    failures: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let mut expected: Vec<String> = crate_spec_index()
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

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

fn display_repo_path(path: &Path) -> String {
    let root = workspace_root();
    path.strip_prefix(root.join("crates"))
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn assert_contains(findings: &[String], needle: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(needle)),
        "expected finding containing `{needle}`, got {findings:?}"
    );
}

fn assert_not_contains(findings: &[String], needle: &str) {
    assert!(
        findings.iter().all(|finding| !finding.contains(needle)),
        "expected no finding containing `{needle}`, got {findings:?}"
    );
}
