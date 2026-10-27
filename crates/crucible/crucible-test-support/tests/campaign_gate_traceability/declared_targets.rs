//! Resolves campaign library and integration targets through declared ownership.
//!
//! The selected architecture input is immutable for an audit process. Each
//! process caches its parsed view so requirements that share gate contracts do
//! not repeatedly deserialize the complete workspace graph. Qualification runs
//! each modified graph in a fresh process.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::{test_targets, workspace};

static TARGETS: OnceLock<Result<Option<test_targets::TestTargets>, String>> = OnceLock::new();

fn load() -> io::Result<Option<&'static test_targets::TestTargets>> {
    TARGETS
        .get_or_init(|| test_targets::load().map_err(|error| error.to_string()))
        .as_ref()
        .map(Option::as_ref)
        .map_err(|error| io::Error::other(error.clone()))
}

pub(super) fn library_findings(root: &Path, gate: &str, package: &str) -> Vec<String> {
    match load() {
        Ok(Some(targets)) => match targets.library_findings(root, package) {
            Ok(findings) => findings
                .into_iter()
                .map(|finding| format!("{gate}: {finding}"))
                .collect(),
            Err(error) => vec![format!("{gate}: invalid declared library target: {error}")],
        },
        Ok(None) => {
            let manifest =
                workspace::package_path(&root.join("crates"), package).join("Cargo.toml");
            if manifest.is_file() {
                Vec::new()
            } else {
                vec![format!(
                    "{gate}: library package manifest {} is missing",
                    manifest.display()
                )]
            }
        }
        Err(error) => vec![format!(
            "{gate}: invalid declared campaign targets: {error}"
        )],
    }
}

pub(super) fn integration_directory(
    root: &Path,
    gate: &str,
    package: &str,
    test: &str,
    require_manifest: bool,
    findings: &mut Vec<String>,
) -> Option<PathBuf> {
    match load() {
        Ok(Some(targets)) => {
            let directory = match targets.package_directory(package) {
                Ok(directory) => root.join(directory),
                Err(error) => {
                    findings.push(format!(
                        "{gate}: invalid declared integration owner: {error}"
                    ));
                    return None;
                }
            };
            let required: Vec<_> = crate::gate_targets()
                .iter()
                .filter(|target| target.package == package && target.test_target == test)
                .flat_map(|target| target.required_features.iter().copied())
                .collect();
            match targets.integration_findings(package, test, &required) {
                Ok(actual) => findings.extend(
                    actual
                        .into_iter()
                        .map(|finding| format!("{gate}: {finding}")),
                ),
                Err(error) => findings.push(format!(
                    "{gate}: invalid declared integration target: {error}"
                )),
            }
            Some(directory)
        }
        Ok(None) => {
            let directory = workspace::package_path(&root.join("crates"), package);
            let manifest = directory.join("Cargo.toml");
            if require_manifest && !manifest.is_file() {
                findings.push(format!(
                    "{gate}: integration package manifest {} is missing",
                    manifest.display()
                ));
            }
            Some(directory)
        }
        Err(error) => {
            findings.push(format!(
                "{gate}: invalid declared campaign targets: {error}"
            ));
            None
        }
    }
}
