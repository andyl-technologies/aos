//! Immutable descriptors selecting deployment evaluation sources and artifacts.
//!
//! ```json
//! {"schema":"aos.package.evaluation-input","library":"/nix/store/00000000000000000000000000000000-library/default.nix","scope":["profile","system"]}
//! ```
//!
//! The descriptor contains full package and source catalogs; decoding checks
//! these relationships before any source is read or any handler is executed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Result, ensure};
use aos_core::Sha256Digest;
use aos_module_format::graph::GRAPH_LIMITS;
use serde::{Deserialize, Serialize};

use crate::model::ResolvedPackages;
use crate::resolution_lock::ResolutionLock;

/// Describes the admitted immutable inputs before evaluating a package graph.
///
/// The descriptor contains no output graph or self locator. Package-owned
/// operations can retain its path as ordinary input without a reference cycle.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationInput {
    /// Identifies the native pre-evaluation input contract.
    pub schema: String,
    /// Locates the immutable generic module library entrypoint.
    pub library: PathBuf,
    /// Binds the library root to its admitted NAR identity.
    #[serde(rename = "libraryNarHash")]
    pub library_nar_hash: Sha256Digest,
    /// Identifies the stable profile or deployment scope.
    pub scope: Vec<String>,
    /// Contains the exact resolved package modules and payload artifacts.
    pub packages: ResolvedPackages,
    /// Retains each resolved module's original authenticated deployment envelope.
    #[serde(rename = "moduleEnvelopes")]
    pub module_envelopes: std::collections::BTreeMap<String, PathBuf>,
    /// Retains selected payload envelopes, including packages without a module.
    #[serde(default, rename = "packageEnvelopes")]
    pub package_envelopes: BTreeMap<String, PathBuf>,
    /// Pins the host release used for runtime compatibility checks.
    #[serde(default, rename = "osRelease", skip_serializing_if = "Option::is_none")]
    pub os_release: Option<aos_module_docs::runtime::OsRelease>,
    /// Pins ranged dependency choices; exact-only closures omit this field.
    #[serde(
        default,
        rename = "resolutionLock",
        skip_serializing_if = "Option::is_none"
    )]
    pub resolution_lock: Option<ResolutionLock>,
    /// Orders the retained baseline module sources.
    pub configuration: Vec<PathBuf>,
    /// Orders the replaceable operator module snapshot entrypoints.
    #[serde(default, rename = "runtimeConfiguration")]
    pub runtime_configuration: Vec<PathBuf>,
    /// Retains immutable authority and domain artifacts without importing them as modules.
    #[serde(default, rename = "supplementalInputs")]
    pub supplemental_inputs: Vec<PathBuf>,
}

impl EvaluationInput {
    /// Decodes and validates a bounded native descriptor without reading its sources.
    ///
    /// # Errors
    /// Returns an error for malformed data, an unsupported schema, an empty
    /// scope, or noncanonical immutable source locators.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let input: Self = GRAPH_LIMITS.decode(bytes, "native evaluation input")?;
        ensure!(
            input.schema == "aos.package.evaluation-input",
            "unsupported native evaluation input"
        );
        ensure!(
            !input.scope.is_empty() && input.scope.iter().all(|segment| !segment.is_empty()),
            "native evaluation scope is empty"
        );
        for source in std::iter::once(&input.library)
            .chain(&input.configuration)
            .chain(&input.runtime_configuration)
            .chain(&input.supplemental_inputs)
        {
            crate::locator::store_root_and_suffix(source)?;
        }
        for supplemental in &input.supplemental_inputs {
            let (root, suffix) = crate::locator::store_root_and_suffix(supplemental)?;
            ensure!(
                root == *supplemental && suffix.as_os_str().is_empty(),
                "supplemental input must name a canonical store root"
            );
        }
        let mut module_names = std::collections::BTreeSet::new();
        for module in &input.packages.modules {
            ensure!(
                module_names.insert(&module.name),
                "resolved module names are duplicated"
            );
        }
        ensure!(
            module_names == input.module_envelopes.keys().collect(),
            "module envelope catalog differs from resolved module names"
        );
        let payloads: BTreeSet<_> = input
            .packages
            .artifacts
            .iter()
            .map(|artifact| artifact.canonical_catalog().path)
            .collect();
        ensure!(
            payloads == input.package_envelopes.keys().cloned().collect(),
            "selected payloads differ from retained envelope catalog"
        );

        if let Some(release) = &input.os_release {
            ensure!(
                !release.name.is_empty()
                    && release.name.len() <= 256
                    && release.version.len() <= 128
                    && semver::Version::parse(&release.version).is_ok(),
                "retained host release has an invalid name or semantic version"
            );
        }
        for path in input
            .module_envelopes
            .values()
            .chain(input.package_envelopes.values())
        {
            let (root, suffix) = crate::locator::store_root_and_suffix(path)?;
            ensure!(
                root == *path && suffix.as_os_str().is_empty(),
                "module envelope must name a canonical store root"
            );
        }
        ensure!(
            input.resolution_lock.is_some()
                || input
                    .packages
                    .modules
                    .iter()
                    .all(|module| module.module_requirements.is_empty()),
            "ranged module requirements have no exact resolution lock"
        );
        if let Some(lock) = &input.resolution_lock {
            lock.check()?;
        }
        Ok(input)
    }
}
