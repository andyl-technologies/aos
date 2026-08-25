//! Checks the RFC-0010 file/module, layer-boundary, and commit-hygiene rules.
//!
//! The crate layer DAG is checked by `crate_layer_graph`; this test owns the
//! adjacent source-shape and review-policy rules from RFC-0010 file 28 section
//! 5 so drift is caught before those standards become prose-only guidance.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

use crucible_harness::spec_index::crate_spec_index;

const SOFT_LINE_LIMIT: usize = 600;
const HARD_LINE_LIMIT: usize = 1_000;
const QEMU_BOUNDARY_PACKAGES: &[&str] = &[
    "crucible-debug-gateway",
    "crucible-daemon",
    "crucible-qemu",
    "crucible-qemu-plugin",
];
const QEMU_SPECIFIC_TOKENS: &[&str] = &[
    "qemu",
    "Qemu",
    "QEMU",
    "qmp",
    "Qmp",
    "QMP",
    "savevm",
    "loadvm",
    "crucible_qemu",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommitHygieneRule {
    id: &'static str,
    required_doc_terms: &'static [&'static str],
}

#[derive(Clone, Debug, Default)]
struct HygieneBaseline {
    line_limit_debt: BTreeMap<String, usize>,
    missing_header_debt: BTreeSet<String>,
    qemu_token_debt: BTreeSet<(String, String, String)>,
    qemu_manifest_debt: BTreeSet<(String, String, String, String)>,
}

const COMMIT_HYGIENE_RULES: &[CommitHygieneRule] = &[
    CommitHygieneRule {
        id: "atomic-logical-change",
        required_doc_terms: &["focused and atomic", "logical change"],
    },
    CommitHygieneRule {
        id: "imperative-summary",
        required_doc_terms: &["imperative summary"],
    },
    CommitHygieneRule {
        id: "abi-golden-engine-together",
        required_doc_terms: &["versioned ABI", "golden-vector", "engine logic"],
    },
    CommitHygieneRule {
        id: "no-determinism-format-churn",
        required_doc_terms: &["determinism-relevant change", "unrelated formatting churn"],
    },
];

#[test]
fn crucible_source_modules_follow_size_and_header_limits() -> Result<(), Box<dyn Error>> {
    let root = repo_root();
    let baseline = HygieneBaseline::load(&root)?;
    let mut failures = Vec::new();

    for spec in crate_spec_index() {
        let package_dir = root.join("crates").join(spec.package);
        for source in rust_sources(&package_dir)? {
            let content = fs::read_to_string(&source)?;
            failures.extend(
                source_shape_failures(&source, &content)
                    .into_iter()
                    .filter(|finding| !baseline.allows_source_shape(&source, &content, finding)),
            );
        }
    }
    failures.extend(baseline.stale_source_shape_failures(&root)?);

    assert!(
        failures.is_empty(),
        "Crucible engineering hygiene source-shape failures:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn non_qemu_crates_do_not_define_against_qemu_specific_boundaries() -> Result<(), Box<dyn Error>> {
    let root = repo_root();
    let baseline = HygieneBaseline::load(&root)?;
    let mut failures = Vec::new();

    for spec in crate_spec_index() {
        let package_dir = root.join("crates").join(spec.package);
        let manifest_path = package_dir.join("Cargo.toml");
        let manifest = fs::read_to_string(&manifest_path)?;
        failures.extend(
            qemu_manifest_boundary_failures(spec.package, &manifest_path, &manifest)
                .into_iter()
                .filter(|finding| {
                    !baseline.allows_qemu_manifest(spec.package, &manifest_path, finding)
                }),
        );

        for source in rust_sources(&package_dir.join("src"))? {
            let content = fs::read_to_string(&source)?;
            failures.extend(
                qemu_specific_boundary_failures(spec.package, &source, &content)
                    .into_iter()
                    .filter(|finding| !baseline.allows_qemu_token(spec.package, &source, finding)),
            );
        }
    }
    failures.extend(baseline.stale_qemu_token_failures(&root)?);
    failures.extend(baseline.stale_qemu_manifest_failures(&root)?);

    assert!(
        failures.is_empty(),
        "Crucible engineering hygiene boundary failures:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn engineering_hygiene_policy_is_wired_and_documented() -> Result<(), Box<dyn Error>> {
    let root = repo_root();
    let standards =
        fs::read_to_string(root.join("docs/rfcs/0010-crucible/28-engineering-standards.md"))?;
    let default_nix = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    let hygiene_nix =
        fs::read_to_string(root.join("tests/crucible/phase1-engineering-hygiene.nix"))?;
    let layer_graph_nix = root.join("tests/crucible/phase1-crate-layer-graph.nix");
    let mut failures = Vec::new();

    failures.extend(commit_hygiene_policy_failures(&standards, &hygiene_nix));
    require_contains(
        &default_nix,
        "engineeringHygiene = import ./phase1-engineering-hygiene.nix",
        "tests/crucible/default.nix must wire checks.crucible.phase1.engineeringHygiene",
        &mut failures,
    );
    require_contains(
        &default_nix,
        "crateLayerGraph = import ./phase1-crate-layer-graph.nix",
        "tests/crucible/default.nix must keep the layer-boundary DAG check wired",
        &mut failures,
    );
    if !layer_graph_nix.is_file() {
        failures.push(format!(
            "{}: missing crate layer-graph mirror for STD-28",
            display_repo_path(&layer_graph_nix)
        ));
    }
    require_contains(
        &hygiene_nix,
        "tasks=T-STD-11",
        "phase1 engineering hygiene check must claim T-STD-11",
        &mut failures,
    );
    require_contains(
        &hygiene_nix,
        "file_soft_limit=600",
        "phase1 engineering hygiene check must publish the soft line limit",
        &mut failures,
    );
    require_contains(
        &hygiene_nix,
        "file_hard_limit=1000",
        "phase1 engineering hygiene check must publish the hard line limit",
        &mut failures,
    );

    assert!(
        failures.is_empty(),
        "Crucible engineering hygiene policy failures:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn engineering_hygiene_rules_reject_shape_and_boundary_drift() {
    let no_header =
        source_shape_failures(Path::new("synthetic.rs"), "pub fn missing_header() {}\n");
    assert_contains(&no_header, "missing `//!` module header");

    let exact_soft = format!(
        "//! synthetic\n{}",
        "fn line() {}\n".repeat(SOFT_LINE_LIMIT - 1)
    );
    let exact_soft_findings = source_shape_failures(Path::new("synthetic.rs"), &exact_soft);
    assert!(
        !exact_soft_findings
            .iter()
            .any(|finding| finding.contains("line limit")),
        "{exact_soft_findings:?}"
    );

    let soft_limit = format!(
        "//! synthetic\n{}",
        "fn line() {}\n".repeat(SOFT_LINE_LIMIT)
    );
    let soft_findings = source_shape_failures(Path::new("synthetic.rs"), &soft_limit);
    assert_contains(&soft_findings, "exceeds soft line limit");

    let exact_hard = format!(
        "//! synthetic\n{}",
        "fn line() {}\n".repeat(HARD_LINE_LIMIT - 1)
    );
    let exact_hard_findings = source_shape_failures(Path::new("synthetic.rs"), &exact_hard);
    assert!(
        !exact_hard_findings
            .iter()
            .any(|finding| finding.contains("hard line limit")),
        "{exact_hard_findings:?}"
    );

    let hard_limit = format!(
        "//! synthetic\n{}",
        "fn line() {}\n".repeat(HARD_LINE_LIMIT)
    );
    let hard_findings = source_shape_failures(Path::new("synthetic.rs"), &hard_limit);
    assert_contains(&hard_findings, "exceeds hard line limit");

    let forbidden = qemu_specific_boundary_failures(
        "crucible",
        Path::new("crucible/src/backend.rs"),
        "pub struct QemuNode;\n",
    );
    assert_contains(&forbidden, "QEMU-specific token");

    let allowed = qemu_specific_boundary_failures(
        "crucible-qemu",
        Path::new("crucible-qemu/src/lib.rs"),
        "pub struct QemuNode;\n",
    );
    assert!(allowed.is_empty(), "{allowed:?}");

    let commented = qemu_specific_boundary_failures(
        "crucible",
        Path::new("crucible/src/backend.rs"),
        r#"
            //! QEMU appears in docs only.
            const TEXT: &str = "QemuNode appears in a diagnostic";
            pub struct ProtocolNode;
        "#,
    );
    assert!(commented.is_empty(), "{commented:?}");

    let root_manifest = r#"
        [dependencies]
        vm_driver = { package = "crucible-qemu", path = "../crucible-qemu" }
    "#;
    let root_manifest_findings =
        qemu_manifest_boundary_failures("crucible-session", Path::new("Cargo.toml"), root_manifest);
    assert_contains(&root_manifest_findings, "QEMU boundary dependency");

    let target_manifest = r#"
        [target.'cfg(unix)'.dev-dependencies]
        plugin_driver = { package = "crucible-qemu-plugin", path = "../crucible-qemu-plugin" }
    "#;
    let target_manifest_findings = qemu_manifest_boundary_failures(
        "crucible-session",
        Path::new("Cargo.toml"),
        target_manifest,
    );
    assert_contains(&target_manifest_findings, "QEMU boundary dependency");

    let allowed_manifest_findings =
        qemu_manifest_boundary_failures("crucible-qemu", Path::new("Cargo.toml"), target_manifest);
    assert!(
        allowed_manifest_findings.is_empty(),
        "{allowed_manifest_findings:?}"
    );
}

impl HygieneBaseline {
    fn load(root: &Path) -> Result<Self, Box<dyn Error>> {
        let content =
            fs::read_to_string(root.join("tests/crucible/engineering-hygiene-baseline.txt"))?;
        let mut baseline = Self::default();

        for (line_index, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields = line.split('|').collect::<Vec<_>>();
            match fields.as_slice() {
                ["shape-line", path, max_lines] => {
                    let max_lines = max_lines.parse::<usize>().map_err(|source| {
                        IoError::new(
                            ErrorKind::InvalidData,
                            format!(
                                "invalid line-cap baseline entry on line {}: {source}",
                                line_index + 1
                            ),
                        )
                    })?;
                    baseline
                        .line_limit_debt
                        .insert((*path).to_string(), max_lines);
                }
                ["shape-header", path] => {
                    baseline.missing_header_debt.insert((*path).to_string());
                }
                ["qemu-token", package, path, token] => {
                    baseline.qemu_token_debt.insert((
                        (*package).to_string(),
                        (*path).to_string(),
                        (*token).to_string(),
                    ));
                }
                ["qemu-manifest", package, path, dependency, scope] => {
                    baseline.qemu_manifest_debt.insert((
                        (*package).to_string(),
                        (*path).to_string(),
                        (*dependency).to_string(),
                        (*scope).to_string(),
                    ));
                }
                _ => {
                    return Err(IoError::new(
                        ErrorKind::InvalidData,
                        format!(
                            "invalid engineering hygiene baseline entry on line {}: {line}",
                            line_index + 1
                        ),
                    )
                    .into());
                }
            }
        }

        Ok(baseline)
    }

    fn allows_source_shape(&self, path: &Path, content: &str, finding: &str) -> bool {
        let relative = display_repo_path(path);
        if finding.contains("line limit") {
            return self
                .line_limit_debt
                .get(&relative)
                .is_some_and(|max_lines| source_line_count(content) <= *max_lines);
        }

        finding.contains("missing `//!` module header")
            && self.missing_header_debt.contains(&relative)
    }

    fn allows_qemu_token(&self, package: &str, path: &Path, finding: &str) -> bool {
        let relative = display_repo_path(path);
        QEMU_SPECIFIC_TOKENS.iter().any(|token| {
            finding.contains(&format!("token `{token}`"))
                && self.qemu_token_debt.contains(&(
                    package.to_string(),
                    relative.clone(),
                    (*token).to_string(),
                ))
        })
    }

    fn allows_qemu_manifest(&self, package: &str, path: &Path, finding: &str) -> bool {
        let relative = display_repo_path(path);
        QEMU_BOUNDARY_PACKAGES.iter().any(|dependency| {
            dependency_scopes().iter().any(|scope| {
                finding.contains(&format!("dependency `{dependency}`"))
                    && finding.contains(&format!("section `{scope}`"))
                    && self.qemu_manifest_debt.contains(&(
                        package.to_string(),
                        relative.clone(),
                        (*dependency).to_string(),
                        (*scope).to_string(),
                    ))
            })
        })
    }

    fn stale_source_shape_failures(&self, root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
        let mut failures = Vec::new();

        for (relative, max_lines) in &self.line_limit_debt {
            let path = root.join(relative);
            let content = fs::read_to_string(&path)?;
            let line_count = source_line_count(&content);
            if line_count <= SOFT_LINE_LIMIT {
                failures.push(format!(
                    "tests/crucible/engineering-hygiene-baseline.txt: stale shape-line baseline `{relative}` cap {max_lines} observed {line_count}"
                ));
            }
        }

        for relative in &self.missing_header_debt {
            let path = root.join(relative);
            let content = fs::read_to_string(&path)?;
            if content.starts_with("//!") {
                failures.push(format!(
                    "tests/crucible/engineering-hygiene-baseline.txt: stale shape-header baseline `{relative}`"
                ));
            }
        }

        Ok(failures)
    }

    fn stale_qemu_token_failures(&self, root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
        let mut failures = Vec::new();

        for (package, relative, token) in &self.qemu_token_debt {
            let path = root.join(relative);
            let content = fs::read_to_string(&path)?;
            let token_finding = format!("token `{token}`");
            let still_observed = qemu_specific_boundary_failures(package, &path, &content)
                .iter()
                .any(|finding| finding.contains(&token_finding));
            if !still_observed {
                failures.push(format!(
                    "tests/crucible/engineering-hygiene-baseline.txt: stale qemu-token baseline `{package}|{relative}|{token}`"
                ));
            }
        }

        Ok(failures)
    }

    fn stale_qemu_manifest_failures(&self, root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
        let mut failures = Vec::new();

        for (package, relative, dependency, scope) in &self.qemu_manifest_debt {
            let path = root.join(relative);
            let manifest = fs::read_to_string(&path)?;
            let dependency_finding = format!("dependency `{dependency}`");
            let scope_finding = format!("section `{scope}`");
            let still_observed = qemu_manifest_boundary_failures(package, &path, &manifest)
                .iter()
                .any(|finding| {
                    finding.contains(&dependency_finding) && finding.contains(&scope_finding)
                });
            if !still_observed {
                failures.push(format!(
                    "tests/crucible/engineering-hygiene-baseline.txt: stale qemu-manifest baseline `{package}|{relative}|{dependency}|{scope}`"
                ));
            }
        }

        Ok(failures)
    }
}

fn source_shape_failures(path: &Path, content: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let line_count = source_line_count(content);

    if line_count > HARD_LINE_LIMIT {
        failures.push(format!(
            "{}: {line_count} lines exceeds hard line limit {HARD_LINE_LIMIT}",
            display_repo_path(path)
        ));
    } else if line_count > SOFT_LINE_LIMIT {
        failures.push(format!(
            "{}: {line_count} lines exceeds soft line limit {SOFT_LINE_LIMIT}",
            display_repo_path(path)
        ));
    }

    if !content.starts_with("//!") {
        failures.push(format!(
            "{}: missing `//!` module header",
            display_repo_path(path)
        ));
    }

    failures
}

fn source_line_count(content: &str) -> usize {
    content.lines().count()
}

fn qemu_specific_boundary_failures(package: &str, path: &Path, content: &str) -> Vec<String> {
    if QEMU_BOUNDARY_PACKAGES.contains(&package) {
        return Vec::new();
    }

    let scrubbed = scrub_comments_and_strings(content);
    QEMU_SPECIFIC_TOKENS
        .iter()
        .filter(|token| scrubbed.contains(**token))
        .map(|token| {
            format!(
                "{}: QEMU-specific token `{token}` appears outside the QEMU boundary in `{package}`",
                display_repo_path(path)
            )
        })
        .collect()
}

fn qemu_manifest_boundary_failures(package: &str, path: &Path, manifest: &str) -> Vec<String> {
    if QEMU_BOUNDARY_PACKAGES.contains(&package) {
        return Vec::new();
    }

    let Ok(document) = manifest.parse::<toml::Value>() else {
        return vec![format!("{}: invalid Cargo.toml", display_repo_path(path))];
    };

    dependency_package_names(&document)
        .into_iter()
        .filter(|(_, dependency)| QEMU_BOUNDARY_PACKAGES.contains(&dependency.as_str()))
        .map(|(scope, dependency)| {
            format!(
                "{}: QEMU boundary dependency `{dependency}` appears in `{package}` manifest section `{scope}`",
                display_repo_path(path)
            )
        })
        .collect()
}

fn dependency_package_names(document: &toml::Value) -> Vec<(String, String)> {
    let mut dependencies = Vec::new();
    collect_dependency_table(document, "dependencies", "dependencies", &mut dependencies);
    collect_dependency_table(
        document,
        "dev-dependencies",
        "dev-dependencies",
        &mut dependencies,
    );
    collect_dependency_table(
        document,
        "build-dependencies",
        "build-dependencies",
        &mut dependencies,
    );

    if let Some(targets) = document.get("target").and_then(toml::Value::as_table) {
        for (target, target_doc) in targets {
            collect_dependency_table(
                target_doc,
                "dependencies",
                &format!("target.{target}.dependencies"),
                &mut dependencies,
            );
            collect_dependency_table(
                target_doc,
                "dev-dependencies",
                &format!("target.{target}.dev-dependencies"),
                &mut dependencies,
            );
            collect_dependency_table(
                target_doc,
                "build-dependencies",
                &format!("target.{target}.build-dependencies"),
                &mut dependencies,
            );
        }
    }

    dependencies
}

fn collect_dependency_table(
    document: &toml::Value,
    lookup_section: &str,
    report_scope: &str,
    dependencies: &mut Vec<(String, String)>,
) {
    let Some(table) = document.get(lookup_section).and_then(toml::Value::as_table) else {
        return;
    };

    for (alias, dependency) in table {
        let package = dependency
            .get("package")
            .and_then(toml::Value::as_str)
            .unwrap_or(alias)
            .to_string();
        dependencies.push((report_scope.to_string(), package));
    }
}

fn dependency_scopes() -> &'static [&'static str] {
    &["dependencies", "dev-dependencies", "build-dependencies"]
}

fn commit_hygiene_policy_failures(standards: &str, hygiene_nix: &str) -> Vec<String> {
    let mut failures = Vec::new();

    for rule in COMMIT_HYGIENE_RULES {
        for term in rule.required_doc_terms {
            require_contains(
                standards,
                term,
                &format!("STD-29 must document commit hygiene term `{term}`"),
                &mut failures,
            );
        }
        require_contains(
            hygiene_nix,
            rule.id,
            &format!(
                "phase1 engineering hygiene check must publish rule `{}`",
                rule.id
            ),
            &mut failures,
        );
    }

    failures
}

fn rust_sources(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut sources = Vec::new();
    collect_rust_sources(dir, &mut sources)?;
    sources.sort();
    Ok(sources)
}

fn collect_rust_sources(dir: &Path, sources: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn display_repo_path(path: &Path) -> String {
    let root = repo_root();
    path.strip_prefix(&root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn require_contains(content: &str, needle: &str, failure: &str, failures: &mut Vec<String>) {
    if !content.contains(needle) {
        failures.push(failure.to_string());
    }
}

fn scrub_comments_and_strings(content: &str) -> String {
    let mut output = String::with_capacity(content.len());
    let chars: Vec<char> = content.chars().collect();
    let mut index = 0;
    let mut state = ScannerState::Code;

    while index < chars.len() {
        match state {
            ScannerState::Code => {
                if chars[index] == '/' && chars.get(index + 1) == Some(&'/') {
                    output.push_str("  ");
                    index += 2;
                    state = ScannerState::LineComment;
                } else if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
                    output.push_str("  ");
                    index += 2;
                    state = ScannerState::BlockComment { depth: 1 };
                } else if chars[index] == '"' {
                    output.push(' ');
                    index += 1;
                    state = ScannerState::String;
                } else {
                    output.push(chars[index]);
                    index += 1;
                }
            }
            ScannerState::LineComment => {
                if chars[index] == '\n' {
                    output.push('\n');
                    state = ScannerState::Code;
                } else {
                    output.push(' ');
                }
                index += 1;
            }
            ScannerState::BlockComment { depth } => {
                if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
                    output.push_str("  ");
                    index += 2;
                    state = ScannerState::BlockComment { depth: depth + 1 };
                } else if chars[index] == '*' && chars.get(index + 1) == Some(&'/') {
                    output.push_str("  ");
                    index += 2;
                    state = if depth == 1 {
                        ScannerState::Code
                    } else {
                        ScannerState::BlockComment { depth: depth - 1 }
                    };
                } else {
                    output.push(if chars[index] == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
            ScannerState::String => {
                if chars[index] == '\\' && chars.get(index + 1).is_some() {
                    output.push(' ');
                    output.push(if chars[index + 1] == '\n' { '\n' } else { ' ' });
                    index += 2;
                } else if chars[index] == '"' {
                    output.push(' ');
                    index += 1;
                    state = ScannerState::Code;
                } else {
                    output.push(if chars[index] == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
        }
    }

    output
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScannerState {
    Code,
    LineComment,
    BlockComment { depth: usize },
    String,
}

fn assert_contains(findings: &[String], reason: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(reason)),
        "expected finding containing `{reason}`, got {findings:?}"
    );
}
