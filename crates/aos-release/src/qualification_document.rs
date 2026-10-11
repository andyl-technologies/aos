//! Validates location-independent, package-owned native qualification companions.
//!
//! The following format excerpt abbreviates the operation bodies:
//!
//! ```json
//! {"schema":"aos.package.qualification","package":{"name":"example","version":"1"},
//! "selectors":[],"artifacts":[],"probe":{"primary":{},"bad_input":{}}}
//! ```
//!
//! The operation bodies are closed typed projections of package authoring. Store
//! paths belong to the frozen `artifacts` bindings; the portable probe and
//! selector templates remain independent of source locations.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::Deserialize;

/// Identifies one package output used by a native qualification recipe.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct QualificationSelector {
    /// Owning package name.
    pub package: String,
    /// Exact named output.
    pub output: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Coordinate {
    name: String,
    version: String,
}

/// Contains a validated, closed native package qualification recipe.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationDocument {
    schema: String,
    package: Coordinate,
    selectors: Vec<QualificationSelector>,
    artifacts: Vec<QualificationBinding>,
    probe: Probe,
}

/// Binds a portable selector to its exact evaluated immutable payload root.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationBinding {
    /// Package output whose ownership is retained by this binding.
    pub selector: QualificationSelector,
    /// Exact immutable output root.
    pub path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    primary: Operation,
    bad_input: Operation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    input: String,
    operation: String,
    expected: String,
    files: BTreeMap<String, Template>,
    steps: Vec<Step>,
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    argv: Vec<Template>,
    #[serde(deserialize_with = "required_option")]
    stdin: Option<Template>,
    #[serde(deserialize_with = "required_option")]
    stdout: Option<Template>,
    #[serde(deserialize_with = "required_option")]
    stderr: Option<Template>,
    exit_code: u8,
    observes_rejection: bool,
    #[serde(deserialize_with = "required_option")]
    timeout_seconds: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Template {
    fragments: Vec<Fragment>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Fragment {
    Literal {
        text: String,
    },
    ArtifactRoot {
        artifact: QualificationSelector,
    },
    ArtifactPath {
        artifact: QualificationSelector,
        path: String,
    },
    WorkPath {
        path: String,
    },
    Harness {
        tool: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Artifact {
    Text { path: String, text: String },
    Sha256 { path: String, digest: String },
}

fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn bounded(value: &str, empty: bool) -> Result<()> {
    ensure!(
        (empty || !value.is_empty()) && value.len() <= 1_048_576 && !value.contains('\0'),
        "qualification string is invalid or exceeds its limit"
    );
    Ok(())
}

fn path(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 4096
            && !value.starts_with('/')
            && !value.contains(['\0', '\n', '\r'])
            && value
                .split('/')
                .all(|part| !matches!(part, "" | "." | "..")),
        "qualification path must be normalized and relative"
    );
    Ok(())
}

impl QualificationSelector {
    fn validate(&self) -> Result<()> {
        aos_registry_surface::manifest::validate_package_name(&self.package)?;
        ensure!(
            !self.output.is_empty()
                && self.output.len() <= 256
                && self
                    .output
                    .as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                && self
                    .output
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'\'')),
            "qualification output name is invalid"
        );
        Ok(())
    }
}

impl Template {
    fn validate(&self, used: &mut BTreeSet<QualificationSelector>) -> Result<()> {
        ensure!(
            !self.fragments.is_empty() && self.fragments.len() <= 64,
            "qualification template fragment count is invalid"
        );
        for fragment in &self.fragments {
            match fragment {
                Fragment::Literal { text } => bounded(text, true)?,
                Fragment::ArtifactRoot { artifact } => {
                    artifact.validate()?;
                    used.insert(artifact.clone());
                }
                Fragment::ArtifactPath {
                    artifact,
                    path: value,
                } => {
                    artifact.validate()?;
                    path(value)?;
                    used.insert(artifact.clone());
                }
                Fragment::WorkPath { path: value } => path(value)?,
                Fragment::Harness { tool } => ensure!(
                    matches!(
                        tool.as_str(),
                        "bash"
                            | "c-compiler"
                            | "cxx-compiler"
                            | "perl"
                            | "python"
                            | "rust-compiler"
                    ),
                    "unsupported qualification harness"
                ),
            }
        }
        Ok(())
    }
}

impl Operation {
    fn validate(&self, used: &mut BTreeSet<QualificationSelector>) -> Result<()> {
        for value in [&self.input, &self.operation, &self.expected] {
            bounded(value, false)?;
        }
        ensure!(
            self.files.len() <= 32
                && !self.steps.is_empty()
                && self.steps.len() <= 16
                && self.artifacts.len() <= 32,
            "qualification operation count exceeds its limit"
        );
        for (name, template) in &self.files {
            path(name)?;
            template.validate(used)?;
        }
        for step in &self.steps {
            ensure!(
                !step.argv.is_empty() && step.argv.len() <= 64,
                "qualification command argument count is invalid"
            );
            ensure!(
                step.timeout_seconds
                    .is_none_or(|value| (1..=300).contains(&value)),
                "qualification timeout is invalid"
            );
            for template in step
                .argv
                .iter()
                .chain(step.stdin.iter())
                .chain(step.stdout.iter())
                .chain(step.stderr.iter())
            {
                template.validate(used)?;
            }
        }
        for artifact in &self.artifacts {
            match artifact {
                Artifact::Text { path: value, text } => {
                    path(value)?;
                    bounded(text, true)?;
                }
                Artifact::Sha256 {
                    path: value,
                    digest,
                } => {
                    path(value)?;
                    aos_contract::Sha256Digest::parse(digest)?;
                }
            }
        }
        Ok(())
    }
}

impl QualificationDocument {
    /// Decodes and validates the exact native qualification projection.
    ///
    /// # Errors
    /// Returns an error for malformed or oversized JSON, unknown fields, invalid
    /// recipes, mismatched owning coordinates, or incomplete selector inventory.
    pub fn decode(bytes: &[u8], name: &str, version: &str) -> Result<Self> {
        let limits = aos_contract::limits::JsonLimits {
            max_bytes: 16_777_216,
            max_depth: 32,
            max_items: 65_536,
            max_string_bytes: 1_048_576,
        };
        let document: Self = limits.decode(bytes, "native package qualification")?;
        ensure!(
            document.schema == "aos.package.qualification"
                && document.package.name == name
                && document.package.version == version,
            "qualification differs from owning package coordinate"
        );
        aos_registry_surface::manifest::validate_package_name(name)?;
        bounded(version, false)?;
        let mut used = BTreeSet::new();
        document.probe.primary.validate(&mut used)?;
        document.probe.bad_input.validate(&mut used)?;
        ensure!(
            document
                .probe
                .primary
                .steps
                .iter()
                .all(|step| step.exit_code == 0),
            "primary qualification commands must succeed"
        );
        ensure!(
            document
                .probe
                .bad_input
                .steps
                .iter()
                .any(|step| step.exit_code != 0 || step.observes_rejection),
            "bad-input qualification must observe rejection"
        );
        let declared: BTreeSet<_> = document.selectors.iter().cloned().collect();
        ensure!(
            declared.len() == document.selectors.len() && declared == used,
            "qualification selectors differ from exact recipe references"
        );
        for selector in &document.selectors {
            selector.validate()?;
        }
        let mut bound = BTreeSet::new();
        for artifact in &document.artifacts {
            artifact.selector.validate()?;
            aos_registry_surface::store::store_path_hash(&artifact.path)?;
            ensure!(
                bound.insert(artifact.selector.clone()),
                "duplicate qualification artifact binding"
            );
        }
        ensure!(
            bound == declared,
            "qualification artifacts differ from recipe selectors"
        );
        Ok(document)
    }

    /// Returns the exact output selectors referenced by this recipe.
    pub fn selectors(&self) -> &[QualificationSelector] {
        &self.selectors
    }

    /// Returns exact evaluated payload bindings for every selector.
    pub fn artifacts(&self) -> &[QualificationBinding] {
        &self.artifacts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> serde_json::Value {
        let template = json!({"fragments":[{"kind":"artifact-path","artifact":{"package":"example","output":"out"},"path":"bin/example"}]});
        let step = json!({"argv":[template],"stdin":null,"stdout":null,"stderr":null,"exit_code":0,"observes_rejection":false,"timeout_seconds":null});
        let primary = json!({"input":"valid","operation":"run","expected":"success","files":{},"steps":[step],"artifacts":[]});
        let mut bad = primary.clone();
        bad["steps"][0]["exit_code"] = json!(7);
        json!({"schema":"aos.package.qualification","package":{"name":"example","version":"1"},"selectors":[{"package":"example","output":"out"}],"artifacts":[{"selector":{"package":"example","output":"out"},"path":"/nix/store/00000000000000000000000000000000-example"}],"probe":{"primary":primary,"bad_input":bad}})
    }
    #[test]
    fn native_recipe_is_closed_and_has_exact_selector_inventory() {
        let mut value = fixture();
        assert!(
            QualificationDocument::decode(&serde_json::to_vec(&value).unwrap(), "example", "1")
                .is_ok()
        );
        assert!(
            QualificationDocument::decode(&serde_json::to_vec(&value).unwrap(), "other", "1")
                .is_err()
        );
        value["selectors"] = json!([]);
        assert!(
            QualificationDocument::decode(&serde_json::to_vec(&value).unwrap(), "example", "1")
                .is_err()
        );
        value = fixture();
        value["probe"]["primary"]["steps"][0]["argv"][0]["fragments"][0]["path"] =
            json!("../escape");
        assert!(
            QualificationDocument::decode(&serde_json::to_vec(&value).unwrap(), "example", "1")
                .is_err()
        );
        value = fixture();
        value["legacy"] = json!({});
        assert!(
            QualificationDocument::decode(&serde_json::to_vec(&value).unwrap(), "example", "1")
                .is_err()
        );
    }
}
