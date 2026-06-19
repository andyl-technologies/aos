//! Checks the RFC-0010 rustdoc standard for Crucible crates.
//!
//! Rustdoc's own lints enforce missing public docs and broken intra-doc links.
//! This harness lint covers the source-shape rules that rustdoc does not model:
//! module headers, crate-root module maps, format sketches for format-owning
//! modules, ASCII comments/docs, and `# Errors`/`# Panics` sections.

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

    if let Some(owner) = format_owner {
        if !has_tagged_format_sketch(&module_docs) {
            failures.push(format!(
                "{display_path}: {owner} module is missing tagged format sketch"
            ));
        }
    }

    failures.extend(ascii_comment_doc_failures(&lines, display_path));
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
