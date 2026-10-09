//! Portable dependency choices retained independently of registry discovery.
//!
//! ```json
//! {"schema":"aos.package.resolution-lock","edges":[],"requesters":{}}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::model::{Artifact, Envelope, ModuleDependency, ModuleSource};

const MAX_CANDIDATES: usize = 16_384;

/// Records one original dependency requirement and its exact selected module.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedEdge {
    /// Identifies the requesting package independently of its selected output.
    pub requester: Artifact,
    /// Preserves the original exact or ranged declaration.
    pub requirement: ModuleDependency,
    /// Pins the chosen module source and package coordinate.
    pub selected: ModuleSource,
}

/// Retains dependency decisions independently of mutable registry catalogs.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionLock {
    /// Identifies the exact dependency lock format.
    pub schema: String,
    /// Records every dependency edge in the selected closure.
    pub edges: Vec<LockedEdge>,
    /// Locates authenticated requester envelopes, including moduleless aggregates.
    pub requesters: BTreeMap<String, PathBuf>,
}

impl ResolutionLock {
    /// Projects authored ranged requirements for declaration documentation.
    #[must_use]
    pub fn module_requirements(&self) -> Vec<aos_module_docs::runtime::ModuleRequirement> {
        self.edges
            .iter()
            .filter_map(|edge| {
                if let ModuleDependency::Ranged {
                    package,
                    package_version,
                } = &edge.requirement
                {
                    Some(aos_module_docs::runtime::ModuleRequirement {
                        owner: edge.requester.name.clone(),
                        package: package.name.clone(),
                        package_version: package_version.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Checks lock structure before its authenticated envelopes are opened.
    ///
    /// # Errors
    /// Returns an error for an unsupported schema, invalid requirements, duplicate
    /// edges, missing requester companions, or noncanonical immutable locators.
    pub fn check(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.package.resolution-lock",
            "unsupported module resolution lock"
        );
        ensure!(
            self.edges.len() <= MAX_CANDIDATES,
            "resolution lock exceeds its edge bound"
        );
        let mut keys = BTreeSet::new();
        for edge in &self.edges {
            edge.requirement.check()?;
            ensure!(
                edge.requester.name != "" && edge.requester.version != "",
                "lock requester has no coordinate"
            );
            ensure!(
                edge.selected.name == edge.requirement.seed().name,
                "lock substitutes another dependency package"
            );
            ModuleDependency::Exact(edge.selected.clone()).check()?;
            ensure!(
                keys.insert((
                    edge.requester.path.clone(),
                    edge.requirement.seed().name.clone()
                )),
                "resolution lock repeats a dependency edge"
            );
        }
        let expected: BTreeSet<_> = self.edges.iter().map(|edge| &edge.requester.path).collect();
        ensure!(
            expected == self.requesters.keys().collect(),
            "resolution lock requester catalog differs from its edges"
        );
        for path in self.requesters.values() {
            let (root, suffix) = crate::locator::store_root_and_suffix(path)?;
            ensure!(
                root == *path && suffix.as_os_str().is_empty(),
                "lock requester envelope is not a store root"
            );
        }
        Ok(())
    }

    /// Validates the closed choices against their original envelope declarations.
    ///
    /// # Errors
    /// Returns an error for missing or extra edges, changed requirements or
    /// module identities or incompatible package requirements.
    pub fn validate(&self, envelopes: &[Envelope]) -> Result<()> {
        self.check()?;
        let mut expected = Vec::new();
        for envelope in envelopes {
            for requirement in &envelope.module_dependencies {
                let selected = envelopes
                    .iter()
                    .find(|candidate| candidate.package.name == requirement.seed().name)
                    .context("locked module dependency is absent")?;
                ensure!(
                    matches_requirement(requirement, selected)?,
                    "locked module does not satisfy its original requirement"
                );
                expected.push(LockedEdge {
                    requester: envelope.package.canonical_catalog(),
                    requirement: requirement.clone(),
                    selected: selected
                        .module
                        .clone()
                        .context("locked dependency has no module")?,
                });
            }
        }
        let canonical = |edges: &[LockedEdge]| -> Result<Vec<Vec<u8>>> {
            let mut bytes = edges
                .iter()
                .map(serde_json::to_vec)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            bytes.sort();
            ensure!(
                bytes.windows(2).all(|pair| pair[0] != pair[1]),
                "resolution lock repeats an edge"
            );
            Ok(bytes)
        };
        ensure!(
            canonical(&expected)? == canonical(&self.edges)?,
            "resolution lock differs from original dependency edges"
        );
        Ok(())
    }
}

/// Checks whether an authenticated candidate satisfies a dependency declaration.
///
/// # Errors
/// Returns an error when the requirement's version constraint is invalid.
pub fn matches_requirement(requirement: &ModuleDependency, candidate: &Envelope) -> Result<bool> {
    match &candidate.module {
        Some(source) => requirement.accepts(source, &candidate.package.version),
        None => Ok(false),
    }
}
