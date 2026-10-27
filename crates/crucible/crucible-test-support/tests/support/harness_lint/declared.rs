//! Resolves harness dependency and lint policy through declared Bazel targets.
//!
//! The immutable graph is parsed once per audit process. Package ownership and
//! dependency coverage share the structural audit reader; lint-specific records
//! additionally bind each compilation to its own configuration and Clippy root.
//!
//! The lint-specific portion of the architecture document includes records such
//! as the following; configuration levels, aliases, and package roots accompany
//! the compilation bindings in the complete document.
//!
//! ```json
//! {"lint_binding_count": 1, "lint_bindings": {
//!   "//crates/example:lib": {
//!     "package": "example", "kind": "rust_library", "test_only": false,
//!     "configuration_selection": {"type": "LABEL", "values": ["//tools/bazel/rules:workspace_lints"]},
//!     "rustc_flag_selection": {"type": "STRING_LIST", "values": []},
//!     "tag_selection": {"type": "STRING_LIST", "values": []}
//!   }
//! }}
//! ```

use std::io;
use std::sync::OnceLock;

use crate::architecture;

use super::*;

#[path = "lint_selection.rs"]
mod lint_selection;

use lint_selection::Selection;

const SELECTION: &str = "declared Rust compilation lint bindings, lint levels, Clippy roots, and shared configuration-file groups; selectors retained";
static DECLARED: OnceLock<Result<Option<Declared>, String>> = OnceLock::new();

/// Holds checked source ownership, dependency edges, and lint declarations.
pub(super) struct Declared {
    architecture: architecture::Architecture,
    document: Document,
}

#[derive(serde::Deserialize)]
struct Document {
    lint_target_selection: String,
    lint_configuration_count: usize,
    lint_configurations: BTreeMap<String, Configuration>,
    lint_binding_count: usize,
    lint_bindings: BTreeMap<String, Binding>,
    clippy_target_count: usize,
    clippy_targets: BTreeMap<String, ClippyTarget>,
    alias_target_count: usize,
    alias_targets: BTreeMap<String, Selection<Vec<String>>>,
    lint_data_group_count: usize,
    lint_data_groups: BTreeMap<String, Selection<Vec<String>>>,
}

#[derive(serde::Deserialize)]
struct Configuration {
    rustc: Selection<BTreeMap<String, String>>,
    clippy: Selection<BTreeMap<String, String>>,
    rustdoc: Selection<BTreeMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct Binding {
    package: String,
    kind: String,
    test_only: bool,
    configuration_selection: Selection<Vec<String>>,
    rustc_flag_selection: Selection<Vec<String>>,
    tag_selection: Selection<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct ClippyTarget {
    package: String,
    kind: String,
    test_only: bool,
    target_selection: Selection<Vec<String>>,
}

/// Loads the selected graph without falling back after a declared-input error.
///
/// # Errors
///
/// Returns an error for absent, malformed, incomplete, or inconsistent metadata.
pub(super) fn load() -> io::Result<Option<&'static Declared>> {
    DECLARED
        .get_or_init(|| read().map_err(|error| error.to_string()))
        .as_ref()
        .map(Option::as_ref)
        .map_err(|error| io::Error::other(error.clone()))
}

fn read() -> io::Result<Option<Declared>> {
    let Some(architecture) = architecture::load()? else {
        return Ok(None);
    };
    let path = std::env::var_os("AOS_BAZEL_ARCHITECTURE")
        .ok_or_else(|| io::Error::other("missing declared lint architecture input"))?;
    let document = serde_json::from_str(&fs::read_to_string(path)?).map_err(io::Error::other)?;
    let declared = Declared {
        architecture,
        document,
    };
    declared.validate()?;
    Ok(Some(declared))
}

impl Declared {
    fn validate(&self) -> io::Result<()> {
        let document = &self.document;
        if document.lint_target_selection != SELECTION
            || document.lint_configuration_count != document.lint_configurations.len()
            || document.lint_binding_count != document.lint_bindings.len()
            || document.clippy_target_count != document.clippy_targets.len()
            || document.alias_target_count != document.alias_targets.len()
            || document.lint_data_group_count != document.lint_data_groups.len()
        {
            return Err(io::Error::other(
                "declared lint selection or counts disagree",
            ));
        }

        let dependencies = self.architecture.dependency_targets()?;
        let compilations: BTreeSet<_> = dependencies
            .iter()
            .filter(|(_, target)| {
                matches!(
                    target.kind.as_str(),
                    "rust_library"
                        | "rust_binary"
                        | "rust_proc_macro"
                        | "rust_shared_library"
                        | "rust_static_library"
                        | "rust_test"
                )
            })
            .map(|(label, _)| label)
            .collect();
        if compilations != document.lint_bindings.keys().collect() {
            return Err(io::Error::other(
                "declared lint compilation coverage disagrees",
            ));
        }
        let clippy_targets: BTreeSet<_> = dependencies
            .iter()
            .filter(|(_, target)| target.kind == "rust_clippy")
            .map(|(label, _)| label)
            .collect();
        if clippy_targets != document.clippy_targets.keys().collect() {
            return Err(io::Error::other(
                "declared Clippy target coverage disagrees",
            ));
        }

        for configuration in document.lint_configurations.values() {
            for levels in [
                &configuration.rustc,
                &configuration.clippy,
                &configuration.rustdoc,
            ] {
                levels.validate("STRING_DICT")?;
                if levels.alternatives().into_iter().any(|branch| {
                    branch.iter().any(|(name, level)| {
                        name.is_empty()
                            || !matches!(
                                level.as_str(),
                                "allow" | "warn" | "deny" | "forbid" | "force-warn"
                            )
                    })
                }) {
                    return Err(io::Error::other("invalid declared lint level"));
                }
            }
        }
        for selection in document.alias_targets.values() {
            selection.validate("LABEL")?;
            if selection
                .alternatives()
                .iter()
                .any(|branch| branch.len() != 1)
            {
                return Err(io::Error::other("invalid declared lint alias"));
            }
        }
        for selection in document.lint_data_groups.values() {
            selection.validate("LABEL_LIST")?;
        }
        for (label, binding) in &document.lint_bindings {
            let target = dependencies
                .get(label)
                .ok_or_else(|| io::Error::other("missing declared lint compilation"))?;
            if binding.package != target.package
                || binding.kind != target.kind
                || binding.test_only != target.test_only
            {
                return Err(io::Error::other(
                    "declared lint compilation ownership disagrees",
                ));
            }
            binding.configuration_selection.validate("LABEL")?;
            binding.rustc_flag_selection.validate("STRING_LIST")?;
            binding.tag_selection.validate("STRING_LIST")?;
            if binding
                .configuration_selection
                .alternatives()
                .iter()
                .any(|branch| branch.len() > 1)
            {
                return Err(io::Error::other(
                    "invalid declared lint configuration binding",
                ));
            }
            for configuration in binding.configuration_selection.union() {
                self.configurations(configuration, &mut BTreeSet::new())?;
            }
        }
        for (label, clippy) in &document.clippy_targets {
            let target = dependencies
                .get(label)
                .ok_or_else(|| io::Error::other("missing declared Clippy target"))?;
            clippy.target_selection.validate("LABEL_LIST")?;
            let labels: BTreeSet<_> = target
                .dependencies
                .iter()
                .filter(|edge| edge.attribute == "deps")
                .map(|edge| edge.label.as_str())
                .collect();
            if clippy.package != target.package
                || clippy.kind != target.kind
                || clippy.test_only != target.test_only
                || clippy.target_selection.union() != labels
            {
                return Err(io::Error::other(
                    "declared Clippy ownership or roots disagree",
                ));
            }
        }
        Ok(())
    }

    fn configurations<'a>(
        &'a self,
        label: &str,
        active: &mut BTreeSet<String>,
    ) -> io::Result<Vec<&'a Configuration>> {
        if let Some(configuration) = self.document.lint_configurations.get(label) {
            return Ok(vec![configuration]);
        }
        if !active.insert(label.to_owned()) {
            return Err(io::Error::other("declared lint configuration alias cycle"));
        }
        let selection = self
            .document
            .alias_targets
            .get(label)
            .ok_or_else(|| io::Error::other("missing declared lint configuration"))?;
        let mut result = Vec::new();
        for target in selection.union() {
            result.extend(self.configurations(target, active)?);
        }
        active.remove(label);
        Ok(result)
    }

    /// Returns the package's repository-relative source directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the package has no declared owner.
    pub(super) fn directory(&self, package: &str) -> io::Result<&Path> {
        self.architecture.package_directory(package)
    }

    /// Checks production engine edges at nondeterministic process boundaries.
    ///
    /// # Errors
    ///
    /// Returns an error when a boundary package has no production graph.
    pub(super) fn boundary_findings(&self, package: &str) -> io::Result<Vec<String>> {
        if !NONDETERMINISTIC_BOUNDARY_PACKAGES.contains(&package)
            || matches!(
                package,
                "crucible-cli" | "crucible-daemon" | "crucible-qemu-host"
            )
        {
            return Ok(Vec::new());
        }
        let dependencies = self.architecture.production_dependencies(package)?;
        Ok(if dependencies.contains("crucible-engine") {
            vec![format!(
                "`{package}` may not route host nondeterminism directly into engine State; declared production dependency must cross an API/session boundary or the crucible-sim decision source"
            )]
        } else {
            Vec::new()
        })
    }

    /// Returns package dependencies across production and development branches.
    ///
    /// # Errors
    ///
    /// Returns an error for absent ownership or incomplete dependency metadata.
    pub(super) fn dependencies(&self, package: &str) -> io::Result<BTreeSet<&str>> {
        self.architecture.package_directory(package)?;
        Ok(self
            .architecture
            .dependency_targets()?
            .values()
            .filter(|target| target.package == package)
            .flat_map(|target| &target.dependencies)
            .flat_map(|edge| edge.packages.iter().map(String::as_str))
            .collect())
    }

    /// Checks lint inheritance, complete package roots, and configured input data.
    ///
    /// # Errors
    ///
    /// Returns an error for missing configured inputs, invalid ownership, or
    /// unreadable configuration and build-wiring sources.
    pub(super) fn clippy_findings(&self, repo: &Path) -> io::Result<Vec<String>> {
        let mut findings = Vec::new();
        for package in crate_spec_index().iter().map(|spec| spec.package) {
            let directory = self.directory(package)?;
            let label = format!("//{}:clippy_all", directory.display());
            let Some(root) = self.document.clippy_targets.get(&label) else {
                findings.push(format!(
                    "{package}: missing declared all-target Clippy root"
                ));
                continue;
            };
            let guaranteed = root.target_selection.guaranteed();
            for (label, binding) in self
                .document
                .lint_bindings
                .iter()
                .filter(|(_, binding)| binding.package == package)
            {
                if !guaranteed.contains(label.as_str()) {
                    findings.push(format!("{label}: missing all-target Clippy coverage"));
                }
                if binding
                    .configuration_selection
                    .alternatives()
                    .iter()
                    .any(|branch| branch.is_empty())
                {
                    findings.push(format!(
                        "{label}: missing explicit declared lint inheritance"
                    ));
                }
                for configuration in binding.configuration_selection.union() {
                    for configuration in self.configurations(configuration, &mut BTreeSet::new())? {
                        for lint in CLIPPY_DENY_LINTS {
                            if !configuration.clippy.guarantees_deny(lint) {
                                findings.push(format!("{label}: declared Clippy configuration must guarantee deny `{lint}`"));
                            }
                        }
                    }
                }
                if binding.tag_selection.union().iter().any(|tag| {
                    matches!(
                        tag.replace('-', "_").to_lowercase().as_str(),
                        "no_clippy" | "no_lint" | "nolint" | "noclippy"
                    )
                }) || binding.rustc_flag_selection.union().iter().any(|flag| {
                    flag.starts_with("--cap-lints")
                        || flag.starts_with("--allow")
                        || flag.starts_with("--warn")
                        || flag.starts_with("--force-warn")
                        || flag.starts_with("-A")
                        || flag.starts_with("-W")
                }) {
                    findings.push(format!(
                        "{label}: declared flags or tags weaken the lint tier"
                    ));
                }
            }
        }

        let configured = std::env::var_os("AOS_BAZEL_CLIPPY_CONFIG")
            .ok_or_else(|| io::Error::other("missing declared Clippy configuration input"))?;
        let configured = PathBuf::from(configured);
        let group = self
            .document
            .lint_data_groups
            .get("//tools/bazel/rules:clippy_config")
            .ok_or_else(|| io::Error::other("missing declared Clippy configuration-file group"))?;
        let files = group
            .union()
            .into_iter()
            .map(source_file)
            .collect::<io::Result<Vec<_>>>()?;
        if !files
            .iter()
            .any(|relative| repo.join(relative) == configured)
        {
            return Err(io::Error::other(
                "configured Clippy input has no declared file ownership",
            ));
        }
        let content = fs::read_to_string(configured)?;
        if let Some(config) =
            clippy::parse_toml("declared Clippy configuration", &content, &mut findings)
        {
            for method in CLIPPY_DISALLOWED_METHODS {
                if !clippy::toml_array_has_path(&config, "disallowed-methods", method) {
                    findings.push(format!(
                        "declared Clippy configuration: missing disallowed method `{method}`"
                    ));
                }
            }
            for kind in CLIPPY_DISALLOWED_TYPES {
                if !clippy::toml_array_has_path(&config, "disallowed-types", kind) {
                    findings.push(format!(
                        "declared Clippy configuration: missing disallowed type `{kind}`"
                    ));
                }
            }
        }
        let builder =
            fs::read_to_string(repo.join("tests/build/_bazel-crucible-controller-tests.nix"))?;
        for marker in [
            "lint = pkgs.mkAosBazelBuild",
            "targets = clippyTargets",
            ":clippy_all",
        ] {
            if !builder.contains(marker) {
                findings.push(format!("declared Clippy gate wiring lacks `{marker}`"));
            }
        }
        let launcher = fs::read_to_string(repo.join("tools/bazel/launcher.py"))?;
        if !launcher
            .contains("--@rules_rust//rust/settings:clippy.toml=//tools/bazel/rules:clippy_config")
        {
            findings.push("declared Clippy gate wiring lacks the configured filegroup".to_owned());
        }
        Ok(findings)
    }
}

fn source_file(label: &str) -> io::Result<PathBuf> {
    let Some((directory, file)) = label
        .strip_prefix("//")
        .and_then(|label| label.split_once(':'))
    else {
        return Err(io::Error::other(
            "invalid declared Clippy source file label",
        ));
    };
    let path = Path::new(directory).join(file);
    if path
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
        || path.extension().is_none_or(|extension| extension != "toml")
    {
        return Err(io::Error::other(
            "declared Clippy source file escapes its package",
        ));
    }
    Ok(path)
}
