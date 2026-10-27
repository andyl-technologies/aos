//! Validates declared libtest compilations and runnable gate targets.
//!
//! The architecture export keeps compilation roots separate from execution
//! wrappers. Feature and argument selectors retain alternatives instead of
//! treating their union as one executable configuration:
//!
//! ```json
//! {
//!   "test_compilation_targets": {
//!     "//crates/example:gate_binary": {
//!       "package": "example", "crate_roots": ["tests/gate.rs"],
//!       "crate_targets": [], "features": ["test-double"],
//!       "feature_selection": {"type": "STRING_LIST", "values": ["test-double"]},
//!       "test_only": true
//!     }
//!   },
//!   "test_execution_targets": {
//!     "//crates/example:gate": {
//!       "package": "example", "binary": "//crates/example:gate_binary",
//!       "tags": [], "argument_selection": {"type": "STRING_LIST", "values": []},
//!       "test_only": true
//!     }
//!   }
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Component, Path};

use crate::architecture;

const SELECTION: &str = "all declared Rust test compilations and libtest execution wrappers; feature selectors retained";

/// Holds owned test compilations and their independently runnable wrappers.
pub(crate) struct TestTargets {
    architecture: architecture::Architecture,
    compilations: BTreeMap<String, Compilation>,
    executions: BTreeMap<String, Execution>,
}

#[derive(serde::Deserialize)]
struct Document {
    test_target_selection: String,
    test_compilation_count: usize,
    test_compilation_targets: BTreeMap<String, Compilation>,
    test_execution_count: usize,
    test_execution_targets: BTreeMap<String, Execution>,
}

#[derive(serde::Deserialize)]
struct Compilation {
    package: String,
    crate_roots: BTreeSet<String>,
    crate_targets: BTreeSet<String>,
    features: BTreeSet<String>,
    feature_selection: ListSelection,
    test_only: bool,
}

#[derive(serde::Deserialize)]
struct Execution {
    package: String,
    binary: String,
    argument_selection: ListSelection,
    test_only: bool,
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum ListSelection {
    #[serde(rename = "STRING_LIST")]
    Values { values: Vec<String> },
    #[serde(rename = "SELECTOR_LIST")]
    Selectors { elements: Vec<Vec<Branch>> },
}

#[derive(serde::Deserialize)]
struct Branch {
    condition: String,
    values: Vec<String>,
}

impl ListSelection {
    // Concatenated elements contribute together. Alternatives within each
    // element contribute only their intersection to a universal guarantee.
    fn values(&self, guaranteed: bool) -> io::Result<BTreeSet<String>> {
        let elements = match self {
            Self::Values { values } => return Ok(values.iter().cloned().collect()),
            Self::Selectors { elements } => elements,
        };
        if elements.is_empty() {
            return Err(io::Error::other("test selector has no elements"));
        }
        let mut result = BTreeSet::new();
        for branches in elements {
            let Some(first) = branches.first() else {
                return Err(io::Error::other("test selector has no branches"));
            };
            let mut conditions = BTreeSet::new();
            let mut selected: BTreeSet<_> = first.values.iter().cloned().collect();
            for branch in branches {
                if branch.condition.is_empty() || !conditions.insert(&branch.condition) {
                    return Err(io::Error::other(
                        "invalid or duplicate test selector condition",
                    ));
                }
                let values = branch.values.iter().cloned().collect();
                selected = if guaranteed {
                    selected.intersection(&values).cloned().collect()
                } else {
                    selected.union(&values).cloned().collect()
                };
            }
            result.extend(selected);
        }
        Ok(result)
    }

    // Gate discovery needs an unfiltered invocation. A selector that supplies
    // arguments on any branch cannot establish that every case remains runnable.
    fn is_unfiltered(&self) -> io::Result<bool> {
        Ok(self.values(false)?.is_empty())
    }
}

impl TestTargets {
    fn validate(&self) -> io::Result<()> {
        let dependencies = self.architecture.dependency_targets()?;
        let declared: BTreeSet<_> = dependencies
            .iter()
            .filter(|(_, target)| target.kind == "rust_test")
            .map(|(label, _)| label)
            .collect();
        if declared != self.compilations.keys().collect() {
            return Err(io::Error::other(
                "test compilation coverage disagrees with dependency targets",
            ));
        }
        for (label, target) in &self.compilations {
            let owner = self.architecture.package_directory(&target.package)?;
            let dependency = &dependencies[label];
            if !target.test_only
                || !label.starts_with(&format!("//{}:", owner.display()))
                || target.package != dependency.package
                || target.test_only != dependency.test_only
                || target.crate_roots.is_empty()
                || target.crate_roots.iter().any(|root| {
                    !root.ends_with(".rs")
                        || Path::new(root)
                            .components()
                            .any(|part| !matches!(part, Component::Normal(_)))
                })
                || target.feature_selection.values(false)? != target.features
            {
                return Err(io::Error::other(
                    "invalid test compilation ownership or features",
                ));
            }
            if !target.crate_targets.is_empty() {
                let mut roots = BTreeSet::new();
                for inherited in &target.crate_targets {
                    if inherited == label {
                        return Err(io::Error::other("test compilation inherits itself"));
                    }
                    if let Some(compilation) = self.compilations.get(inherited) {
                        if compilation.package != target.package {
                            return Err(io::Error::other(
                                "inherited test compilation has foreign ownership",
                            ));
                        }
                        roots.extend(compilation.crate_roots.iter().cloned());
                    } else {
                        let compilation = self
                            .architecture
                            .compilation_targets(&target.package)?
                            .find(|(label, _)| *label == inherited)
                            .ok_or_else(|| {
                                io::Error::other("inherited test crate has no owned compilation")
                            })?;
                        roots.extend(compilation.1.crate_roots.iter().cloned());
                    }
                }
                if roots != target.crate_roots {
                    return Err(io::Error::other(
                        "inherited test roots disagree with their compilations",
                    ));
                }
            }
        }
        for (label, target) in &self.executions {
            let owner = self.architecture.package_directory(&target.package)?;
            let compilation = self
                .compilations
                .get(&target.binary)
                .ok_or_else(|| io::Error::other("test wrapper omitted its compilation"))?;
            if !target.test_only
                || !label.starts_with(&format!("//{}:", owner.display()))
                || target.package != compilation.package
            {
                return Err(io::Error::other("invalid test wrapper ownership"));
            }
            target.argument_selection.values(false)?;
        }
        Ok(())
    }

    /// Returns the package's declared repository-relative directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the package has no source ownership record.
    pub(crate) fn package_directory(&self, package: &str) -> io::Result<&Path> {
        self.architecture.package_directory(package)
    }

    /// Checks that an integration source has unfiltered, feature-safe wrappers.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed feature or argument selector metadata.
    pub(crate) fn integration_findings(
        &self,
        package: &str,
        test: &str,
        required_features: &[&str],
    ) -> io::Result<Vec<String>> {
        let source = format!("tests/{test}.rs");
        let mut findings = Vec::new();
        let mut unfiltered = false;
        let mut compiled = false;
        for (label, target) in &self.compilations {
            if target.package != package || !target.crate_roots.contains(&source) {
                continue;
            }
            compiled = true;
            if target.crate_roots != BTreeSet::from([source.clone()])
                || !target.crate_targets.is_empty()
            {
                findings.push(format!(
                    "{label}: integration target must pin its exact test source"
                ));
            }
            let guaranteed = target.feature_selection.values(true)?;
            for feature in required_features {
                if !guaranteed.contains(*feature) {
                    findings.push(format!(
                        "{label}: test compilation must guarantee required feature {feature:?}"
                    ));
                }
            }
            for execution in self
                .executions
                .values()
                .filter(|execution| execution.binary == *label)
            {
                unfiltered |= execution.argument_selection.is_unfiltered()?;
            }
        }
        if !compiled {
            findings.push(format!(
                "{package}:{test}: missing declared integration compilation"
            ));
        }
        if !unfiltered {
            findings.push(format!(
                "{package}:{test}: missing unfiltered runnable test wrapper"
            ));
        }
        Ok(findings)
    }
}

/// Loads and validates gate-discovery metadata when the Bazel backend is selected.
///
/// # Errors
///
/// Returns an error for absent runtime inputs, incomplete target coverage,
/// inconsistent ownership, or invalid feature and argument selections.
pub(crate) fn load() -> io::Result<Option<TestTargets>> {
    let Some(architecture) = architecture::load()? else {
        return Ok(None);
    };
    let path = std::env::var_os("AOS_BAZEL_ARCHITECTURE").ok_or_else(|| {
        io::Error::other("Bazel gate audit omitted its declared architecture input")
    })?;
    let document: Document =
        serde_json::from_str(&fs::read_to_string(path)?).map_err(io::Error::other)?;
    if document.test_target_selection != SELECTION
        || document.test_compilation_count == 0
        || document.test_execution_count == 0
        || document.test_compilation_count != document.test_compilation_targets.len()
        || document.test_execution_count != document.test_execution_targets.len()
    {
        return Err(io::Error::other(
            "invalid or incomplete declared test target coverage",
        ));
    }
    let targets = TestTargets {
        architecture,
        compilations: document.test_compilation_targets,
        executions: document.test_execution_targets,
    };
    targets.validate()?;
    Ok(Some(targets))
}
