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
use sha2::{Digest, Sha256};

#[path = "support/source_sections.rs"]
mod source_sections;

use source_sections::*;

const RESPONSIBILITY_REVIEW_LINE_THRESHOLD: usize = 1_000;
const COHESION_REVIEW_LINE_THRESHOLD: usize = 1_500;
const LEGACY_SHAPE_LINE_STALE_THRESHOLD: usize = 600;
const COHESION_NOT_REQUIRED: &str = "threshold-not-reached";
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
    source_reviews: BTreeMap<(String, SourceRole), SourceReview>,
    missing_header_debt: BTreeSet<String>,
    qemu_token_debt: BTreeSet<(String, String, String)>,
    qemu_manifest_debt: BTreeSet<(String, String, String, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SourceRole {
    Implementation,
    Tests,
}

impl SourceRole {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "implementation" => Some(Self::Implementation),
            "tests" => Some(Self::Tests),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Implementation => "implementation",
            Self::Tests => "tests",
        }
    }

    const fn lines(self, counts: SourceRoleLineCounts) -> usize {
        match self {
            Self::Implementation => counts.implementation,
            Self::Tests => counts.tests,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceReview {
    digest: String,
    lines: usize,
    responsibilities: String,
    cohesion: String,
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
                    .filter(|finding| !baseline.allows_missing_header(&source, finding)),
            );
            failures.extend(baseline.source_review_failures(&package_dir, &source, &content));
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
        "responsibility_review_threshold=1000",
        "phase1 engineering hygiene check must publish the responsibility-review threshold",
        &mut failures,
    );
    require_contains(
        &hygiene_nix,
        "cohesion_review_threshold=1500",
        "phase1 engineering hygiene check must publish the cohesion-review threshold",
        &mut failures,
    );
    require_contains(
        &hygiene_nix,
        "shape-review",
        "phase1 engineering hygiene check must consume content-bound source reviews",
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

    let exact_review = format!(
        "//! synthetic\n{}",
        "fn line() {}\n".repeat(RESPONSIBILITY_REVIEW_LINE_THRESHOLD - 1)
    );
    let exact_review_findings = HygieneBaseline::default().source_review_failures(
        Path::new("crucible-example"),
        Path::new("crucible-example/src/synthetic.rs"),
        &exact_review,
    );
    assert!(
        exact_review_findings.is_empty(),
        "{exact_review_findings:?}"
    );

    let over_review = format!("{exact_review}fn line() {{}}\n");
    let over_review_findings = HygieneBaseline::default().source_review_failures(
        Path::new("crucible-example"),
        Path::new("crucible-example/src/synthetic.rs"),
        &over_review,
    );
    assert_contains(&over_review_findings, "responsibility review above 1000");

    let mixed = format!(
        "//! synthetic\n{}#[cfg(test)]\nmod tests {{\n{}}}\n",
        "fn implementation() {}\n".repeat(499),
        "fn test_case() {}\n".repeat(1_197),
    );
    let counts = source_role_line_counts(
        Path::new("crucible-example"),
        Path::new("crucible-example/src/synthetic.rs"),
        &mixed,
    );
    assert_eq!(counts.implementation, 500);
    assert_eq!(counts.tests, 1_200);
    let mixed_findings = HygieneBaseline::default().source_review_failures(
        Path::new("crucible-example"),
        Path::new("crucible-example/src/synthetic.rs"),
        &mixed,
    );
    assert_eq!(mixed_findings.len(), 1, "{mixed_findings:?}");
    assert_contains(&mixed_findings, "tests section");

    let test_support_counts = source_role_line_counts(
        Path::new("crucible-example"),
        Path::new("crucible-example/src/node/test_support/large.rs"),
        &"fn support() {}\n".repeat(1_200),
    );
    assert_eq!(test_support_counts.implementation, 0);
    assert_eq!(test_support_counts.tests, 1_200);

    let test_support_module_counts = source_role_line_counts(
        Path::new("crucible-example"),
        Path::new("crucible-example/src/test_support.rs"),
        &"fn support() {}\n".repeat(1_200),
    );
    assert_eq!(test_support_module_counts.implementation, 0);
    assert_eq!(test_support_module_counts.tests, 1_200);

    let stacked_attribute = "//! synthetic\n#[cfg(test)]\n#[allow(dead_code, unused_variables)]\nfn gated(value: (u8, u8)) {\n    let _ = value;\n}\nfn production() {}\n";
    let stacked_counts = source_role_line_counts(
        Path::new("crucible-example"),
        Path::new("crucible-example/src/stacked.rs"),
        stacked_attribute,
    );
    assert_eq!(stacked_counts.implementation, 2);
    assert_eq!(stacked_counts.tests, 5);

    let cfg_field = "//! synthetic\nstruct Example {\n    #[cfg(test)]\n    #[allow(dead_code)]\n    gated: Option<(u8, u8)>,\n    production: u8,\n}\n";
    let cfg_field_counts = source_role_line_counts(
        Path::new("crucible-example"),
        Path::new("crucible-example/src/field.rs"),
        cfg_field,
    );
    assert_eq!(cfg_field_counts.implementation, 4);
    assert_eq!(cfg_field_counts.tests, 3);

    let cfg_expression = "//! synthetic\n#[cfg(test)]\nlet outcome = if condition {\n    1\n} else {\n    2\n};\nfn production() {}\n";
    let cfg_expression_counts = source_role_line_counts(
        Path::new("crucible-example"),
        Path::new("crucible-example/src/expression.rs"),
        cfg_expression,
    );
    assert_eq!(cfg_expression_counts.implementation, 2);
    assert_eq!(cfg_expression_counts.tests, 6);

    let fake_crate_cfg = "//! synthetic\nconst TEXT: &str = r###\"\n#![cfg(test)]\n\"quoted raw content\"\n\"###;\n/* #![cfg(test)] */\nfn production() {}\n";
    assert!(!is_test_support_only_source(fake_crate_cfg));

    let real_crate_cfg =
        "#![cfg(any(test, feature = \"test-support\"))]\n//! synthetic\nfn support() {}\n";
    assert!(is_test_support_only_source(real_crate_cfg));

    let platform_or_test = "#![cfg(any(test, unix))]\n//! synthetic\nfn production() {}\n";
    assert!(!is_test_support_only_source(platform_or_test));

    let nested_crate_cfg = "//! synthetic\nmod support {\n    #![cfg(test)]\n    fn nested() {}\n}\nfn production() {}\n";
    assert!(!is_test_support_only_source(nested_crate_cfg));

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
                    if baseline
                        .line_limit_debt
                        .insert((*path).to_string(), max_lines)
                        .is_some()
                    {
                        return Err(invalid_baseline_entry(
                            line_index,
                            "duplicate shape-line path",
                        ));
                    }
                }
                [
                    "shape-review",
                    path,
                    digest,
                    role,
                    lines,
                    responsibilities,
                    cohesion,
                ] => {
                    let role = SourceRole::parse(role).ok_or_else(|| {
                        invalid_baseline_entry(line_index, "invalid source-review role")
                    })?;
                    let lines = lines.parse::<usize>().map_err(|source| {
                        invalid_baseline_entry(
                            line_index,
                            &format!("invalid source-review line count: {source}"),
                        )
                    })?;
                    if !valid_sha256_digest(digest) {
                        return Err(invalid_baseline_entry(
                            line_index,
                            "invalid source-review SHA-256 digest",
                        ));
                    }
                    if responsibilities.trim().is_empty() || cohesion.trim().is_empty() {
                        return Err(invalid_baseline_entry(
                            line_index,
                            "source-review rationale fields must be nonempty",
                        ));
                    }
                    let key = ((*path).to_string(), role);
                    let review = SourceReview {
                        digest: (*digest).to_string(),
                        lines,
                        responsibilities: (*responsibilities).to_string(),
                        cohesion: (*cohesion).to_string(),
                    };
                    if baseline.source_reviews.insert(key, review).is_some() {
                        return Err(invalid_baseline_entry(
                            line_index,
                            "duplicate source-review path and role",
                        ));
                    }
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

        baseline.validate_unique_review_rationales()?;

        Ok(baseline)
    }

    fn allows_missing_header(&self, path: &Path, finding: &str) -> bool {
        let relative = display_repo_path(path);
        finding.contains("missing `//!` module header")
            && self.missing_header_debt.contains(&relative)
    }

    fn source_review_failures(
        &self,
        package_dir: &Path,
        path: &Path,
        content: &str,
    ) -> Vec<String> {
        let relative = display_repo_path(path);
        let counts = source_role_line_counts(package_dir, path, content);
        let grandfathered = self
            .line_limit_debt
            .get(&relative)
            .is_some_and(|limit| source_line_count(content) <= *limit);
        let digest = source_digest(content);
        let mut failures = Vec::new();

        for role in [SourceRole::Implementation, SourceRole::Tests] {
            let lines = role.lines(counts);
            let key = (relative.clone(), role);
            let review = self.source_reviews.get(&key);

            if lines <= RESPONSIBILITY_REVIEW_LINE_THRESHOLD {
                if review.is_some() {
                    failures.push(format!(
                        "{relative}: stale {} source review at {lines} lines",
                        role.name()
                    ));
                }
                continue;
            }
            if grandfathered && review.is_none() {
                continue;
            }
            let Some(review) = review else {
                failures.push(format!(
                    "{relative}: {} section has {lines} lines and requires a content-bound responsibility review above {RESPONSIBILITY_REVIEW_LINE_THRESHOLD}",
                    role.name()
                ));
                continue;
            };

            if review.digest != digest {
                failures.push(format!(
                    "{relative}: {} source-review digest is stale",
                    role.name()
                ));
            }
            if review.lines != lines {
                failures.push(format!(
                    "{relative}: {} source-review line count {} does not match {lines}",
                    role.name(),
                    review.lines
                ));
            }
            if lines > COHESION_REVIEW_LINE_THRESHOLD {
                if review.cohesion == COHESION_NOT_REQUIRED {
                    failures.push(format!(
                        "{relative}: {} section has {lines} lines and requires a cohesion rationale above {COHESION_REVIEW_LINE_THRESHOLD}",
                        role.name()
                    ));
                }
            } else if review.cohesion != COHESION_NOT_REQUIRED {
                failures.push(format!(
                    "{relative}: {} source review must use `{COHESION_NOT_REQUIRED}` at {lines} lines",
                    role.name()
                ));
            }
        }

        failures
    }

    fn validate_unique_review_rationales(&self) -> Result<(), Box<dyn Error>> {
        let mut responsibilities = BTreeSet::new();
        let mut cohesion = BTreeSet::new();
        for review in self.source_reviews.values() {
            if !responsibilities.insert(review.responsibilities.as_str()) {
                return Err(invalid_baseline_entry(
                    0,
                    "source-review responsibilities must be file-specific",
                ));
            }
            if review.cohesion != COHESION_NOT_REQUIRED
                && !cohesion.insert(review.cohesion.as_str())
            {
                return Err(invalid_baseline_entry(
                    0,
                    "source-review cohesion rationales must be file-specific",
                ));
            }
        }
        Ok(())
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
            if !path.is_file() {
                failures.push(format!(
                    "tests/crucible/engineering-hygiene-baseline.txt: shape-line path `{relative}` does not exist"
                ));
                continue;
            }

            let content = fs::read_to_string(&path)?;
            let line_count = source_line_count(&content);
            if line_count <= LEGACY_SHAPE_LINE_STALE_THRESHOLD {
                failures.push(format!(
                    "tests/crucible/engineering-hygiene-baseline.txt: stale shape-line baseline `{relative}` cap {max_lines} observed {line_count}"
                ));
            }
        }

        for (relative, role) in self.source_reviews.keys() {
            if !root.join(relative).is_file() {
                failures.push(format!(
                    "tests/crucible/engineering-hygiene-baseline.txt: source-review path `{relative}` for {} does not exist",
                    role.name()
                ));
            }
        }

        for relative in &self.missing_header_debt {
            let path = root.join(relative);
            if !path.is_file() {
                failures.push(format!(
                    "tests/crucible/engineering-hygiene-baseline.txt: shape-header path `{relative}` does not exist"
                ));
                continue;
            }

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

fn source_digest(content: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(content.as_bytes()))
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn invalid_baseline_entry(line_index: usize, reason: &str) -> Box<dyn Error> {
    let location = if line_index == 0 {
        String::from("global validation")
    } else {
        format!("line {}", line_index + 1)
    };
    IoError::new(
        ErrorKind::InvalidData,
        format!("invalid engineering hygiene baseline entry at {location}: {reason}"),
    )
    .into()
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
