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

#[path = "support/rustdoc_bar_clap.rs"]
mod rustdoc_bar_clap;
#[path = "support/rustdoc_bar_docs.rs"]
mod rustdoc_bar_docs;
#[path = "support/rustdoc_bar_public.rs"]
mod rustdoc_bar_public;

use rustdoc_bar_clap::*;
use rustdoc_bar_docs::*;
use rustdoc_bar_public::*;

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
