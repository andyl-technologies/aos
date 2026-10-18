//! Package compatibility requirements and native module dependency requests.
//!
//! Exact dependencies retain the existing module-source record. A ranged
//! dependency carries its build-time interface seed and package-version
//! constraint; resolution must bind it to authenticated exact artifacts:
//!
//! ```json
//! {"package":{"name":"interfaces","version":"7","source":"/nix/store/00000000000000000000000000000000-interfaces","entrypoint":"module.nix"},"packageVersion":"^7.0"}
//! ```

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Identifies retained package module source independently of its payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSource {
    /// Names the declaring package.
    pub name: String,
    /// Identifies the selected source version.
    pub version: String,
    /// Identifies the immutable source directory.
    pub source: String,
    /// Names its relative module entry point.
    pub entrypoint: String,
}

/// Requests an exact module or compatible versions of a seed package.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum ModuleDependency {
    /// Retains the exact authored source identity.
    Exact(ModuleSource),
    /// Resolves compatible releases of the same package name.
    Ranged {
        /// Supplies the build-time interface source; it does not pin runtime resolution.
        package: ModuleSource,
        /// Restricts the dependency package's semantic version.
        #[serde(rename = "packageVersion")]
        package_version: String,
    },
}

/// Projects an authored ranged request without its build-time source locator.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleRequirement {
    /// Names the same dependency package eligible for compatible resolution.
    pub package: String,
    /// Restricts the dependency package's semantic version.
    #[serde(rename = "packageVersion")]
    pub package_version: String,
}

impl From<ModuleSource> for ModuleDependency {
    fn from(source: ModuleSource) -> Self {
        Self::Exact(source)
    }
}

impl ModuleSource {
    /// Checks the canonical immutable source identity.
    ///
    /// # Errors
    /// Returns an error for a missing coordinate, noncanonical store root, or entry point.
    pub fn check(&self) -> Result<()> {
        crate::package_version::validate_package_version(&self.version)?;
        let root = self.source.strip_prefix("/nix/store/");
        ensure!(
            root.is_some_and(|root| !root.is_empty() && !root.contains('/')),
            "module source must identify a canonical store root"
        );
        crate::store::store_path_hash(&self.source)?;
        ensure!(
            !self.name.is_empty() && !self.version.is_empty() && self.entrypoint == "module.nix",
            "invalid package module locator"
        );
        Ok(())
    }
}

impl ModuleDependency {
    /// Tests a same-package candidate against the exact source or every authored range.
    ///
    /// # Errors
    /// Returns an error for malformed requests, candidate source identity, or package versions.
    pub fn accepts(&self, source: &ModuleSource, package_version: &str) -> Result<bool> {
        self.check()?;
        source.check()?;
        ensure!(
            source.version == package_version,
            "candidate module differs from its package version"
        );
        match self {
            Self::Exact(expected) => Ok(expected == source),
            Self::Ranged {
                package,
                package_version,
            } => {
                if package.name != source.name {
                    return Ok(false);
                }
                let Ok(version) = semver::Version::parse(&source.version) else {
                    return Ok(false);
                };
                Ok(semver::VersionReq::parse(package_version)?.matches(&version))
            }
        }
    }

    /// Projects a ranged dependency for runtime module records and documentation.
    #[must_use]
    pub fn requirement(&self) -> Option<ModuleRequirement> {
        match self {
            Self::Exact(_) => None,
            Self::Ranged {
                package,
                package_version,
            } => Some(ModuleRequirement {
                package: package.name.clone(),
                package_version: package_version.clone(),
            }),
        }
    }

    /// Returns the authored exact source or ranged request's build-time seed.
    #[must_use]
    pub fn seed(&self) -> &ModuleSource {
        match self {
            Self::Exact(source)
            | Self::Ranged {
                package: source, ..
            } => source,
        }
    }

    /// Reports whether the dependency requires a reproducible resolved lock.
    #[must_use]
    pub fn is_ranged(&self) -> bool {
        matches!(self, Self::Ranged { .. })
    }

    /// Returns the exact dependency source when no range resolution is required.
    #[must_use]
    pub fn as_exact(&self) -> Option<&ModuleSource> {
        match self {
            Self::Exact(source) => Some(source),
            Self::Ranged { .. } => None,
        }
    }

    /// Checks the authored seed and bounded semantic-version requirements.
    ///
    /// # Errors
    /// Returns an error for invalid source identity or invalid ranges.
    pub fn check(&self) -> Result<()> {
        self.seed().check()?;
        if let Self::Ranged {
            package_version, ..
        } = self
        {
            check_requirement(package_version)?;
        }
        Ok(())
    }
}

impl ModuleRequirement {
    /// Checks the bounded projected dependency name and semantic-version ranges.
    ///
    /// # Errors
    /// Returns an error for absent package identities or invalid ranges.
    pub fn check(&self) -> Result<()> {
        ensure!(
            !self.package.is_empty() && self.package.len() <= 256,
            "invalid module requirement package name"
        );
        check_requirement(&self.package_version)?;
        Ok(())
    }
}

/// Checks a generated shorthand against its normalized strict release version.
///
/// # Errors
/// Returns an error for invalid exact coordinates, malformed requirements, non-SemVer releases, or a
/// shorthand that differs from the declaring package release.
pub fn check_version_requirement(version: &str, requirement: Option<&str>) -> Result<()> {
    crate::package_version::validate_package_version(version)?;
    if let Some(requirement) = requirement {
        check_requirement(requirement)?;
        let parsed = semver::Version::parse(version)?;
        ensure!(
            parsed.to_string() == version,
            "package version is not strict SemVer"
        );
        ensure!(
            ["^", "~", "="]
                .iter()
                .any(|operator| requirement == format!("{operator}{version}")),
            "package version requirement is not a normalized release shorthand"
        );
        ensure!(
            semver::VersionReq::parse(requirement)?.matches(&parsed),
            "package version requirement excludes its own release"
        );
    }
    Ok(())
}

/// Checks package and OS compatibility metadata shared by signed catalogs.
///
/// # Errors
/// Returns an error for invalid ranges, repeated dependencies, or malformed sources.
pub fn check_resolution_metadata(
    os_version: Option<&str>,
    dependencies: &[ModuleDependency],
) -> Result<()> {
    ensure!(
        dependencies.len() <= 16_384,
        "native resolution metadata exceeds its bounds"
    );
    if let Some(requirement) = os_version {
        check_requirement(requirement)?;
    }
    let mut names = BTreeSet::new();
    for dependency in dependencies {
        dependency.check()?;
        ensure!(
            names.insert(&dependency.seed().name),
            "duplicate module dependency"
        );
    }
    Ok(())
}

fn check_requirement(requirement: &str) -> Result<()> {
    ensure!(
        !requirement.is_empty() && requirement.len() <= 4096,
        "semantic version requirement exceeds its bounds"
    );
    let parsed = semver::VersionReq::parse(requirement)?;
    ensure!(
        parsed.comparators.len() <= 32,
        "semantic version requirement has too many comparators"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn source() -> ModuleSource {
        ModuleSource {
            name: "interfaces".into(),
            version: "7.0.0".into(),
            source: "/nix/store/00000000000000000000000000000000-interfaces".into(),
            entrypoint: "module.nix".into(),
        }
    }

    #[test]
    fn exact_dependencies_preserve_source_identity() {
        let dependency = ModuleDependency::Exact(source());
        assert_eq!(
            serde_json::to_value(&dependency).unwrap(),
            serde_json::to_value(source()).unwrap()
        );
        assert!(dependency.accepts(&source(), "7.0.0").unwrap());
    }

    #[test]
    fn package_ranges_are_required_and_round_trip() {
        let value = json!({"package":source(),"packageVersion":"^7.0"});
        let dependency: ModuleDependency = serde_json::from_value(value.clone()).unwrap();
        dependency.check().unwrap();
        assert_eq!(serde_json::to_value(&dependency).unwrap(), value);
        assert!(dependency.accepts(&source(), "7.0.0").unwrap());
        let mut candidate = source();
        candidate.version = "8.0.0".into();
        assert!(!dependency.accepts(&candidate, "8.0.0").unwrap());
        assert!(serde_json::from_value::<ModuleDependency>(json!({"package":source()})).is_err());
        assert!(
            serde_json::from_value::<ModuleDependency>(
                json!({"package":source(),"packageVersion":"^7","abilities":{"filesystem":"^1"}})
            )
            .is_err()
        );
    }

    #[test]
    fn package_ranges_keep_semver_prerelease_matching() {
        let mut candidate = source();
        candidate.version = "7.1.0-beta.2".into();
        let mut dependency = ModuleDependency::Ranged {
            package: source(),
            package_version: "^7.0".into(),
        };

        assert!(!dependency.accepts(&candidate, &candidate.version).unwrap());
        if let ModuleDependency::Ranged {
            package_version, ..
        } = &mut dependency
        {
            *package_version = ">=7.1.0-beta.1, <8.0.0".into();
        }
        assert!(dependency.accepts(&candidate, &candidate.version).unwrap());
    }

    #[test]
    fn generated_requirements_bind_one_operator_to_the_exact_package_release() {
        for operator in ["^", "~", "="] {
            check_version_requirement("7.2.3", Some(&format!("{operator}7.2.3"))).unwrap();
        }
        for requirement in ["^7", ">=7.2.3", "^7.2.3, <8", "^7.2.4", "7.2.3"] {
            assert!(check_version_requirement("7.2.3", Some(requirement)).is_err());
        }
        assert!(check_version_requirement("calver", Some("^7.2.3")).is_err());
        check_version_requirement("calver", None).unwrap();
        assert!(check_version_requirement("^7.2.3", None).is_err());
    }

    #[test]
    fn metadata_rejects_invalid_ranges_and_duplicate_packages() {
        assert!(check_resolution_metadata(Some("invalid"), &[]).is_err());
        assert!(check_resolution_metadata(None, &[source().into(), source().into()]).is_err());
        check_requirement(&vec![">=1.0.0"; 32].join(", ")).unwrap();
        assert!(check_requirement(&vec![">=1.0.0"; 33].join(", ")).is_err());
    }
}
