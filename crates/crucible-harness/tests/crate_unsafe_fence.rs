//! Checks the Crucible crate-root safe/unsafe fence.
//!
//! The crate table in RFC-0010 file 27 is the source of truth for which runtime
//! crates forbid `unsafe` entirely and which crates are explicit unsafe
//! boundaries. This test is the first `gate:harness-lint` shape check: adding a
//! new `crucible-*` package or changing a crate root fence must update this
//! executable list.

#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const SAFE_FENCE: &str = "#![forbid(unsafe_code)]";
const UNSAFE_FENCE: &str = "#![deny(unsafe_op_in_unsafe_fn)]";

#[derive(Clone, Copy)]
struct FenceSpec {
    package: &'static str,
    root: &'static str,
    unsafe_boundary: bool,
    safe_wrapper_contract: &'static [&'static str],
}

const FENCE_SPECS: &[FenceSpec] = &[
    FenceSpec {
        package: "crucible-sim",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-assert",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-shmem",
        root: "src/lib.rs",
        unsafe_boundary: true,
        safe_wrapper_contract: &[
            "Unsafe boundary discipline:",
            "safe typed region accessors",
            "safe SPSC push/pop",
            "wrappers that uphold alignment",
        ],
    },
    FenceSpec {
        package: "crucible-protocol",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-device",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-qemu",
        root: "src/lib.rs",
        unsafe_boundary: true,
        safe_wrapper_contract: &[
            "Unsafe boundary discipline:",
            "public callers use a safe host-driver API",
            "validates process and mapping invariants",
        ],
    },
    FenceSpec {
        package: "crucible-qemu-plugin",
        root: "src/lib.rs",
        unsafe_boundary: true,
        safe_wrapper_contract: &[
            "Unsafe boundary discipline:",
            "validate raw QEMU",
            "delegate to safe Rust shims",
        ],
    },
    FenceSpec {
        package: "crucible-guest",
        root: "src/lib.rs",
        unsafe_boundary: true,
        safe_wrapper_contract: &[
            "Unsafe boundary discipline:",
            "public callers use safe doorbell and marker accessors",
            "guest/register and shared-region invariants",
        ],
    },
    FenceSpec {
        package: "crucible",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-session",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-api",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-daemon",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-cli",
        root: "src/main.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-harness",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
];

#[test]
fn crucible_crate_roots_carry_declared_unsafe_fence() -> Result<(), Box<dyn std::error::Error>> {
    let crates_dir = workspace_crates_dir()?;
    let mut failures = Vec::new();

    assert_expected_crucible_package_set(&crates_dir, &mut failures)?;

    for spec in FENCE_SPECS {
        let root_path = crates_dir.join(spec.package).join(spec.root);
        let content = fs::read_to_string(&root_path)?;
        let active_attrs = crate_root_inner_attributes(&content);
        let required = if spec.unsafe_boundary {
            UNSAFE_FENCE
        } else {
            SAFE_FENCE
        };
        let rejected = if spec.unsafe_boundary {
            SAFE_FENCE
        } else {
            UNSAFE_FENCE
        };

        if !active_attrs.contains(&required) {
            failures.push(format!(
                "{}: missing required crate-root fence `{required}`",
                display_repo_path(&root_path)
            ));
        }

        if active_attrs.contains(&rejected) {
            failures.push(format!(
                "{}: carries contradictory crate-root fence `{rejected}`",
                display_repo_path(&root_path)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Crucible crate unsafe-fence lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn unsafe_boundary_crates_document_safe_wrapper_contracts() -> Result<(), Box<dyn std::error::Error>>
{
    let crates_dir = workspace_crates_dir()?;
    let mut failures = Vec::new();

    for spec in FENCE_SPECS {
        let root_path = crates_dir.join(spec.package).join(spec.root);
        let content = fs::read_to_string(&root_path)?;

        if spec.unsafe_boundary && spec.safe_wrapper_contract.is_empty() {
            failures.push(format!(
                "{}: unsafe boundary has no safe-wrapper contract",
                display_repo_path(&root_path)
            ));
            continue;
        }

        for required in spec.safe_wrapper_contract {
            if !content.contains(required) {
                failures.push(format!(
                    "{}: missing safe-wrapper contract phrase `{required}`",
                    display_repo_path(&root_path)
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "Crucible unsafe-boundary wrapper contract lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn unsafe_usage_is_confined_to_safe_wrapper_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let crates_dir = workspace_crates_dir()?;
    let mut failures = Vec::new();

    for spec in FENCE_SPECS {
        let package_dir = crates_dir.join(spec.package);
        for source in rust_sources(&package_dir)? {
            let content = fs::read_to_string(&source)?;
            failures.extend(unsafe_source_failures(
                &source,
                &content,
                spec.unsafe_boundary,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Crucible unsafe source-boundary lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn crate_root_attribute_scanner_ignores_inactive_fences() {
    let source = r#"
//! Inner docs are allowed before crate attributes.
//! #![forbid(unsafe_code)]
/*
#![forbid(unsafe_code)]
*/
// #![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

fn later_item() {}
#![forbid(unsafe_code)]
"#;

    assert_eq!(
        crate_root_inner_attributes(source),
        vec![UNSAFE_FENCE],
        "only active crate-root inner attributes should be accepted"
    );
}

#[test]
fn unsafe_source_scanner_rejects_boundary_drift() {
    let safe_crate_findings = unsafe_source_failures(
        Path::new("crates/crucible/src/lib.rs"),
        r#"
            pub fn bad() {
                // SAFETY: this crate is not an enumerated unsafe boundary.
                unsafe {}
            }
        "#,
        false,
    );
    assert_contains(
        &safe_crate_findings,
        "outside enumerated unsafe-boundary crate",
    );

    let unsafe_boundary_findings = unsafe_source_failures(
        Path::new("crates/crucible-shmem/src/lib.rs"),
        r#"
            pub unsafe fn leaky_public_api() {}

            unsafe fn leaky_private_helper() {}

            pub trait LeakyTrait {
                unsafe fn leaky_trait_method();
            }

            unsafe extern "C" {
                pub fn raw_ffi_import();
                pub static mut RAW_STATE: u8;
            }

            unsafe extern "C" fn leaky_private_callback() {}

            unsafe impl Send for LeakyRing {}

            fn bare_block() {
                unsafe {}
            }

            fn stale_comment() {
                // SAFETY: separated from the block by a blank line.

                unsafe {}
            }

            fn empty_safety_comment() {
                // SAFETY:
                unsafe {}
            }
        "#,
        true,
    );
    assert_contains(&unsafe_boundary_findings, "unsafe item");
    assert_contains(&unsafe_boundary_findings, "unsafe impl without SAFETY");
    assert_contains(&unsafe_boundary_findings, "public unsafe API");
    assert_contains(&unsafe_boundary_findings, "public unsafe extern item");
    assert_contains(&unsafe_boundary_findings, "bare unsafe block");

    let allowed_boundary_findings = unsafe_source_failures(
        Path::new("crates/crucible-shmem/src/lib.rs"),
        r#"
            pub fn safe_wrapper() {
                // SAFETY: the wrapper validates the pointer before dereference.
                unsafe {}
            }

            unsafe extern "C" {
                fn private_raw_ffi_import();
            }

            // SAFETY: the ring wrapper owns the producer/consumer invariants.
            unsafe impl Send for PrivateRing {}
        "#,
        true,
    );
    assert!(
        allowed_boundary_findings.is_empty(),
        "expected private unsafe helper and safe wrapper sample to pass, got {allowed_boundary_findings:?}"
    );
}

fn crate_root_inner_attributes(source: &str) -> Vec<&str> {
    let mut attrs = Vec::new();
    let mut in_block_comment = false;

    for line in source.lines() {
        let trimmed = line.trim();

        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with("//!") {
            continue;
        }

        if trimmed.starts_with("//") {
            continue;
        }

        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }

        if let Some(attribute) = active_inner_attribute(trimmed) {
            attrs.push(attribute);
            continue;
        }

        break;
    }

    attrs
}

fn active_inner_attribute(line: &str) -> Option<&str> {
    let candidate = match line.split_once("//") {
        Some((before_comment, _comment)) => before_comment.trim_end(),
        None => line,
    };

    candidate.strip_prefix("#![")?;
    Some(candidate)
}

fn unsafe_source_failures(path: &Path, content: &str, unsafe_boundary: bool) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() != Some("unsafe") {
            continue;
        }

        if !unsafe_boundary {
            findings.push(finding(
                path,
                token.line,
                "unsafe keyword outside enumerated unsafe-boundary crate",
                "unsafe",
            ));
            continue;
        }

        if unsafe_callable_item_at(&tokens, index) {
            findings.push(finding(path, token.line, "unsafe item", "unsafe"));
        }

        if unsafe_impl_at(&tokens, index)
            && !has_immediately_preceding_safety_comment(content, token.line)
        {
            findings.push(finding(
                path,
                token.line,
                "unsafe impl without SAFETY",
                "unsafe impl",
            ));
        }

        if unsafe_block_follows(&tokens, index)
            && !has_immediately_preceding_safety_comment(content, token.line)
        {
            findings.push(finding(path, token.line, "bare unsafe block", "unsafe"));
        }

        if public_unsafe_api_at(&tokens, index) {
            findings.push(finding(path, token.line, "public unsafe API", "unsafe"));
        }

        findings.extend(public_unsafe_extern_item_failures(path, &tokens, index));
    }

    findings
}

fn unsafe_callable_item_at(tokens: &[Token], unsafe_index: usize) -> bool {
    matches!(unsafe_item_kind(tokens, unsafe_index), Some("fn" | "trait"))
        || unsafe_extern_function_at(tokens, unsafe_index)
}

fn unsafe_impl_at(tokens: &[Token], unsafe_index: usize) -> bool {
    unsafe_item_kind(tokens, unsafe_index) == Some("impl")
}

fn public_unsafe_api_at(tokens: &[Token], unsafe_index: usize) -> bool {
    item_prefix_contains_pub(tokens, unsafe_index)
        && matches!(
            unsafe_item_kind(tokens, unsafe_index),
            Some("fn" | "trait" | "extern")
        )
}

fn unsafe_item_kind(tokens: &[Token], unsafe_index: usize) -> Option<&str> {
    let next = tokens.get(unsafe_index + 1)?.kind.as_ident()?;
    match next {
        "fn" | "trait" => Some(next),
        "impl" => Some("impl"),
        "extern" => Some("extern"),
        _ => None,
    }
}

fn unsafe_extern_function_at(tokens: &[Token], unsafe_index: usize) -> bool {
    if unsafe_item_kind(tokens, unsafe_index) != Some("extern") {
        return false;
    }

    tokens[unsafe_index + 1..]
        .iter()
        .take_while(|token| !matches!(token.kind, TokenKind::Punct('{') | TokenKind::Punct(';')))
        .any(|token| token.kind.as_ident() == Some("fn"))
}

fn item_prefix_contains_pub(tokens: &[Token], index: usize) -> bool {
    let mut cursor = index;
    while let Some(previous) = cursor.checked_sub(1) {
        let token = &tokens[previous];
        match &token.kind {
            TokenKind::Ident(identifier) if identifier == "pub" => return true,
            TokenKind::Punct(';' | '{' | '}') => return false,
            _ => cursor = previous,
        }
    }

    false
}

fn public_unsafe_extern_item_failures(
    path: &Path,
    tokens: &[Token],
    unsafe_index: usize,
) -> Vec<String> {
    if unsafe_item_kind(tokens, unsafe_index) != Some("extern") {
        return Vec::new();
    }

    let Some(open_brace) = tokens[unsafe_index + 1..]
        .iter()
        .position(|token| matches!(token.kind, TokenKind::Punct('{')))
        .map(|relative| unsafe_index + 1 + relative)
    else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let mut depth = 0usize;
    for token in &tokens[open_brace..] {
        match token.kind {
            TokenKind::Punct('{') => depth += 1,
            TokenKind::Punct('}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }

        if depth == 1 && token.kind.as_ident() == Some("pub") {
            findings.push(finding(
                path,
                token.line,
                "public unsafe extern item",
                "pub item",
            ));
        }
    }

    findings
}

fn unsafe_block_follows(tokens: &[Token], index: usize) -> bool {
    matches!(
        tokens.get(index + 1),
        Some(Token {
            kind: TokenKind::Punct('{'),
            ..
        })
    )
}

fn has_immediately_preceding_safety_comment(content: &str, line: usize) -> bool {
    let Some(previous_line) = line.checked_sub(2) else {
        return false;
    };

    content
        .lines()
        .nth(previous_line)
        .is_some_and(safety_comment_states_invariant)
}

fn safety_comment_states_invariant(candidate: &str) -> bool {
    let Some(invariant) = candidate.trim_start().strip_prefix("// SAFETY:") else {
        return false;
    };

    !invariant.trim().is_empty()
}

fn rust_sources(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut sources = Vec::new();
    collect_rust_sources(dir, &mut sources)?;
    sources.sort();
    Ok(sources)
}

fn collect_rust_sources(
    dir: &Path,
    sources: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            sources.push(path);
        }
    }
    Ok(())
}

fn workspace_crates_dir() -> Result<PathBuf, io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("crucible-harness manifest is not inside crates/"))
}

fn assert_expected_crucible_package_set(
    crates_dir: &Path,
    failures: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut expected: Vec<String> = FENCE_SPECS
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

fn display_repo_path(path: &Path) -> String {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new(""));
    path.strip_prefix(crates_dir)
        .map(|relative| format!("crates/{}", relative.display()))
        .unwrap_or_else(|_| path.display().to_string())
}

fn finding(path: &Path, line: usize, reason: &str, pattern: &str) -> String {
    format!(
        "{}:{line}: banned {reason} pattern `{pattern}`",
        display_repo_path(path)
    )
}

fn tokenize(content: &str) -> Vec<Token> {
    let chars: Vec<char> = content.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;

    while index < chars.len() {
        let ch = chars[index];
        if ch == '\n' {
            line += 1;
            index += 1;
        } else if is_identifier_start(ch) {
            let start = index;
            index += 1;
            while index < chars.len() && is_identifier_continue(chars[index]) {
                index += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Ident(chars[start..index].iter().collect()),
                line,
            });
        } else {
            if matches!(
                ch,
                ':' | '!' | '<' | '>' | '{' | '}' | '(' | ')' | ',' | '.' | '=' | ';' | '&'
            ) {
                tokens.push(Token {
                    kind: TokenKind::Punct(ch),
                    line,
                });
            }
            index += 1;
        }
    }

    tokens
}

fn is_identifier_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_identifier_continue(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    Punct(char),
}

impl TokenKind {
    fn as_ident(&self) -> Option<&str> {
        match self {
            Self::Ident(identifier) => Some(identifier),
            Self::Punct(_) => None,
        }
    }
}

fn scrub_comments_and_strings(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut index = 0;
    let mut state = ScannerState::Code;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            ScannerState::Code => {
                if ch == '/' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::LineComment;
                } else if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(1);
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::String;
                } else if let Some(end) = char_literal_end(&chars, index) {
                    replace_range_with_spaces(&chars, index, end, &mut out);
                    index = end;
                } else if let Some(end) = raw_string_end(&chars, index) {
                    replace_range_with_spaces(&chars, index, end, &mut out);
                    index = end;
                } else {
                    out.push(ch);
                    index += 1;
                }
            }
            ScannerState::LineComment => {
                if ch == '\n' {
                    out.push('\n');
                    state = ScannerState::Code;
                } else {
                    out.push(' ');
                }
                index += 1;
            }
            ScannerState::BlockComment(depth) => {
                if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(depth + 1);
                } else if ch == '*' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    if depth == 1 {
                        state = ScannerState::Code;
                    } else {
                        state = ScannerState::BlockComment(depth - 1);
                    }
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
            ScannerState::String => {
                if ch == '\\' && next.is_some() {
                    out.push(' ');
                    out.push(if next == Some('\n') { '\n' } else { ' ' });
                    index += 2;
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::Code;
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
        }
    }

    out
}

fn raw_string_end(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start) != Some(&'r') {
        return None;
    }

    let mut cursor = start + 1;
    let mut hashes = 0;
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
            let hash_end = cursor + 1 + hashes;
            if hash_end <= chars.len() && chars[cursor + 1..hash_end].iter().all(|ch| *ch == '#') {
                return Some(hash_end);
            }
        }
        cursor += 1;
    }

    Some(chars.len())
}

fn char_literal_end(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start) != Some(&'\'') {
        return None;
    }

    let mut cursor = start + 1;
    if chars.get(cursor) == Some(&'\\') {
        cursor += 2;
    } else {
        cursor += 1;
    }

    if chars.get(cursor) == Some(&'\'') {
        Some(cursor + 1)
    } else {
        None
    }
}

fn replace_range_with_spaces(chars: &[char], start: usize, end: usize, out: &mut String) {
    for ch in &chars[start..end] {
        out.push(if *ch == '\n' { '\n' } else { ' ' });
    }
}

#[derive(Clone, Copy, Debug)]
enum ScannerState {
    Code,
    LineComment,
    BlockComment(usize),
    String,
}

fn assert_contains(findings: &[String], reason: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(reason)),
        "expected finding containing `{reason}`, got {findings:?}"
    );
}
