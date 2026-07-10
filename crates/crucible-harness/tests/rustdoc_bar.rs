//! Checks the RFC-0010 rustdoc standard for Crucible crates.
//!
//! Rustdoc's own lints enforce missing public docs and broken intra-doc links.
//! This harness lint covers the source-shape rules that rustdoc does not model:
//! module headers, crate-root module maps, format sketches for format-owning
//! modules, tagged rustdoc fences, clap derive help text boundaries, ASCII
//! comments/docs, and `# Errors`/`# Panics` sections.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
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
    let baseline = RustdocBarBaseline::load(&root)?;
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

    let failures = baseline.filter_failures(failures);

    assert!(
        failures.is_empty(),
        "Crucible rustdoc-bar lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RustdocBarBaselineKey {
    path: String,
    detail: String,
}

#[derive(Default)]
struct RustdocBarBaseline {
    caps: BTreeMap<RustdocBarBaselineKey, usize>,
}

impl RustdocBarBaseline {
    fn load(root: &Path) -> Result<Self, Box<dyn Error>> {
        let path = root.join("tests/crucible/rustdoc-bar-baseline.txt");
        let content = fs::read_to_string(path)?;
        let mut caps = BTreeMap::new();

        for (index, line) in content.lines().enumerate() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 3 {
                return Err(format!(
                    "invalid rustdoc-bar baseline entry on line {}: {line}",
                    index + 1
                )
                .into());
            }

            let count = fields[2].parse::<usize>().map_err(|error| {
                format!(
                    "invalid rustdoc-bar baseline count on line {}: {error}",
                    index + 1
                )
            })?;
            caps.insert(
                RustdocBarBaselineKey {
                    path: fields[0].to_string(),
                    detail: fields[1].to_string(),
                },
                count,
            );
        }

        Ok(Self { caps })
    }

    fn filter_failures(&self, failures: Vec<String>) -> Vec<String> {
        let mut observed = BTreeMap::new();
        let mut unbaselined = Vec::new();

        for failure in failures {
            let Some(key) = RustdocBarBaselineKey::from_failure(&failure) else {
                unbaselined.push(failure);
                continue;
            };
            let observed_count = observed.entry(key.clone()).or_insert(0usize);
            *observed_count += 1;

            if self
                .caps
                .get(&key)
                .is_some_and(|cap| *observed_count <= *cap)
            {
                continue;
            }

            unbaselined.push(failure);
        }

        for (key, cap) in &self.caps {
            let actual = observed.get(key).copied().unwrap_or_default();
            if actual < *cap {
                unbaselined.push(format!(
                    "tests/crucible/rustdoc-bar-baseline.txt: stale baseline `{}` expected {cap} observed {actual}",
                    key.display()
                ));
            }
        }

        unbaselined
    }
}

impl RustdocBarBaselineKey {
    fn from_failure(failure: &str) -> Option<Self> {
        let (path, detail) = failure
            .split_once(": ")
            .or_else(|| split_line_number_failure(failure))?;
        Some(Self {
            path: path.to_string(),
            detail: detail.to_string(),
        })
    }

    fn display(&self) -> String {
        format!("{}\t{}", self.path, self.detail)
    }
}

fn split_line_number_failure(failure: &str) -> Option<(&str, &str)> {
    let (prefix, detail) = failure.split_once(' ')?;
    let (path, line) = prefix.rsplit_once(':')?;
    line.parse::<usize>().ok()?;
    Some((path, detail))
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
    let crate_private_missing_errors = r#"
//! synthetic module

pub(crate) fn fallible_helper() -> Result<(), ()> {
    Ok(())
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
    assert_not_contains(
        &rustdoc_bar_failures(crate_private_missing_errors, "synthetic.rs", false, None),
        "missing `# Errors`",
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
