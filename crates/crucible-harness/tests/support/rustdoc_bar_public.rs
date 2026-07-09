//! Shared support for `rustdoc_bar_public`.

use super::*;

pub(super) fn public_result_doc_failures(lines: &[&str], display_path: &str) -> Vec<String> {
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

pub(super) fn public_panic_doc_failures(lines: &[&str], display_path: &str) -> Vec<String> {
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
pub(super) struct FunctionContext {
    line: usize,
    name: String,
    signature: String,
    body_contains_panic: bool,
}

pub(super) fn public_functions(lines: &[&str]) -> Vec<FunctionContext> {
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

pub(super) fn is_public_function_start(trimmed: &str) -> bool {
    trimmed.starts_with("pub fn ")
        || trimmed.starts_with("pub async fn ")
        || trimmed.starts_with("pub const fn ")
        || trimmed.starts_with("pub(crate) fn ")
        || trimmed.starts_with("pub(crate) async fn ")
        || trimmed.starts_with("pub(crate) const fn ")
}

pub(super) fn collect_signature(lines: &[&str], start: usize) -> String {
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

pub(super) fn signature_returns_result(signature: &str) -> bool {
    let Some((_before_arrow, after_arrow)) = signature.split_once("->") else {
        return false;
    };
    let return_type = after_arrow
        .split(" where ")
        .next()
        .unwrap_or(after_arrow)
        .split('{')
        .next()
        .unwrap_or(after_arrow)
        .trim();
    return_type.contains("Result")
}

pub(super) fn function_name(signature: &str) -> String {
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

pub(super) fn body_contains_panic(lines: &[&str], start: usize) -> bool {
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

pub(super) fn opening_braces(line: &str) -> usize {
    line.chars().filter(|character| *character == '{').count()
}

pub(super) fn closing_braces(line: &str) -> usize {
    line.chars().filter(|character| *character == '}').count()
}

pub(super) fn doc_block_contains(lines: &[&str], item_line: usize, required: &str) -> bool {
    doc_block_before(lines, item_line)
        .iter()
        .any(|line| line.trim() == required)
}

pub(super) fn doc_block_before(lines: &[&str], item_line: usize) -> Vec<String> {
    let mut docs = Vec::new();
    let mut cursor = item_line;

    while cursor > 0 {
        cursor -= 1;
        let trimmed = lines[cursor].trim_start();

        if trimmed.is_empty()
            || trimmed.starts_with("#[")
            || trimmed.starts_with("// crucible-lint: allow ")
        {
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

pub(super) fn format_owner_for(display_path: &str) -> Option<&'static str> {
    FORMAT_OWNING_SOURCES
        .iter()
        .find_map(|(path, owner)| (*path == display_path).then_some(*owner))
}

pub(super) fn rust_source_files(src_dir: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let mut files = Vec::new();
    collect_rust_source_files(src_dir, &mut files)?;
    files.sort();
    Ok(files)
}

pub(super) fn collect_rust_source_files(
    dir: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), io::Error> {
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

pub(super) fn assert_expected_crucible_package_set(
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

pub(super) fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

pub(super) fn display_repo_path(path: &Path) -> String {
    let root = workspace_root();
    path.strip_prefix(root.join("crates"))
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub(super) fn assert_contains(findings: &[String], needle: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(needle)),
        "expected finding containing `{needle}`, got {findings:?}"
    );
}

pub(super) fn assert_not_contains(findings: &[String], needle: &str) {
    assert!(
        findings.iter().all(|finding| !finding.contains(needle)),
        "expected no finding containing `{needle}`, got {findings:?}"
    );
}
