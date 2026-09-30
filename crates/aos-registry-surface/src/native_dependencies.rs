//! Declaration-derived ability versions and native module dependency requests.
//!
//! Exact dependencies retain the existing module-source record. A ranged
//! dependency carries its build-time interface seed and independent ability
//! constraints; resolution must bind it to authenticated exact artifacts:
//!
//! ```json
//! {"package":{"name":"interfaces","version":"7","source":"/nix/store/00000000000000000000000000000000-interfaces","entrypoint":"module.nix"},"abilities":{"filesystem":"^1.2"},"packageVersion":"^7.0"}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Identifies the independently versioned contract exported by its owning module.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityExport {
    /// Strict semantic version of the ability contract, independent of package version.
    pub version: String,
}

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

/// Requests an exact module or compatible versions of a seed package's abilities.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum ModuleDependency {
    /// Retains the exact authored source identity.
    Exact(ModuleSource),
    /// Resolves the same package name through authenticated ability exports.
    Ranged {
        /// Supplies the build-time interface source; it does not pin runtime resolution.
        package: ModuleSource,
        /// Requests every named ability at its independent semantic-version range.
        abilities: BTreeMap<String, String>,
        /// Optionally restricts the dependency package's own semantic version.
        #[serde(
            rename = "packageVersion",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        package_version: Option<String>,
    },
}

/// Projects an authored ranged request without its build-time source locator.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleRequirement {
    /// Names the same dependency package eligible for compatible resolution.
    pub package: String,
    /// Names every required independently versioned ability contract.
    pub abilities: BTreeMap<String, String>,
    /// Optionally restricts the dependency package's own semantic version.
    #[serde(
        rename = "packageVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_version: Option<String>,
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
    /// Returns an error for malformed requests, candidate source identity, or exported versions.
    pub fn accepts(
        &self,
        source: &ModuleSource,
        package_version: &str,
        exports: &BTreeMap<String, AbilityExport>,
    ) -> Result<bool> {
        self.check()?;
        source.check()?;
        check_resolution_metadata(exports, &[])?;
        ensure!(
            source.version == package_version,
            "candidate module differs from its package version"
        );
        match self {
            Self::Exact(expected) => Ok(expected == source),
            Self::Ranged {
                package,
                abilities,
                package_version,
                ..
            } => {
                if package.name != source.name {
                    return Ok(false);
                }
                if let Some(requirement) = package_version {
                    let Ok(version) = semver::Version::parse(&source.version) else {
                        return Ok(false);
                    };
                    if !semver::VersionReq::parse(requirement)?.matches(&version) {
                        return Ok(false);
                    }
                }
                for (name, requirement) in abilities {
                    let Some(export) = exports.get(name) else {
                        return Ok(false);
                    };
                    if !semver::VersionReq::parse(requirement)?
                        .matches(&semver::Version::parse(&export.version)?)
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
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
                abilities,
                package_version,
            } => Some(ModuleRequirement {
                package: package.name.clone(),
                abilities: abilities.clone(),
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
    /// Returns an error for invalid source identity, absent abilities, or invalid ranges.
    pub fn check(&self) -> Result<()> {
        self.seed().check()?;
        if let Self::Ranged {
            abilities,
            package_version,
            ..
        } = self
        {
            ensure!(
                (!abilities.is_empty() || package_version.is_some()) && abilities.len() <= 1024,
                "ranged module dependency must request ability or package versions"
            );
            for (name, requirement) in abilities {
                check_ability_name(name)?;
                check_requirement(requirement)?;
            }
            if let Some(requirement) = package_version {
                check_requirement(requirement)?;
            }
        }
        Ok(())
    }
}

impl ModuleRequirement {
    /// Checks the bounded projected dependency name and semantic-version ranges.
    ///
    /// # Errors
    /// Returns an error for absent package/ability identities or invalid ranges.
    pub fn check(&self) -> Result<()> {
        ensure!(
            !self.package.is_empty() && self.package.len() <= 256,
            "invalid module requirement package name"
        );
        ensure!(
            (!self.abilities.is_empty() || self.package_version.is_some())
                && self.abilities.len() <= 1024,
            "module requirement must request ability or package versions"
        );
        for (name, requirement) in &self.abilities {
            check_ability_name(name)?;
            check_requirement(requirement)?;
        }
        if let Some(requirement) = &self.package_version {
            check_requirement(requirement)?;
        }
        Ok(())
    }
}

/// Checks the generated export and dependency projection shared by signed catalogs.
///
/// # Errors
/// Returns an error for invalid versions, repeated dependency package names, or malformed sources.
pub fn check_resolution_metadata(
    exports: &BTreeMap<String, AbilityExport>,
    dependencies: &[ModuleDependency],
) -> Result<()> {
    ensure!(
        exports.len() <= 1024 && dependencies.len() <= 16_384,
        "native resolution metadata exceeds its bounds"
    );
    for (name, export) in exports {
        check_ability_name(name)?;
        ensure!(
            export.version.len() <= 128,
            "ability version exceeds its bound"
        );
        let version = semver::Version::parse(&export.version)?;
        ensure!(
            version.to_string() == export.version,
            "ability version is not strict SemVer"
        );
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

fn check_ability_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 256
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
        "invalid stable ability name"
    );
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
    fn exact_dependency_preserves_the_module_source_wire_record() {
        let source = source();
        let dependency = ModuleDependency::Exact(source.clone());

        dependency.check().unwrap();
        assert_eq!(
            serde_json::to_value(&dependency).unwrap(),
            serde_json::to_value(&source).unwrap()
        );
        assert_eq!(dependency.as_exact(), Some(&source));
        assert!(!dependency.is_ranged());
    }

    #[test]
    fn independent_ability_ranges_preserve_the_build_seed() {
        let value = json!({"package":source(),"abilities":{"filesystem":"^1.2"},"packageVersion":">=7.0, <9.0"});
        let dependency: ModuleDependency = serde_json::from_value(value.clone()).unwrap();

        dependency.check().unwrap();
        assert!(dependency.is_ranged());
        assert_eq!(dependency.seed(), &source());
        assert_eq!(serde_json::to_value(&dependency).unwrap(), value);
    }

    #[test]
    fn malformed_or_open_requests_are_rejected() {
        for abilities in [
            json!({}),
            json!({"filesystem":"invalid"}),
            json!({"filesystem":""}),
        ] {
            let dependency: ModuleDependency =
                serde_json::from_value(json!({"package":source(),"abilities":abilities})).unwrap();
            assert!(dependency.check().is_err());
        }
        assert!(serde_json::from_value::<ModuleDependency>(json!({"package":source(),"abilities":{"filesystem":"^1.2"},"url":"https://untrusted.invalid"})).is_err());
        let mut source = source();
        source.source.push_str("/module.nix");
        assert!(source.check().is_err());
    }

    #[test]
    fn exports_require_strict_semver_and_one_dependency_per_package() {
        for version in ["1", "v1.2.3", "01.2.3", "1.2.3 "] {
            let exports = BTreeMap::from([(
                "filesystem".into(),
                AbilityExport {
                    version: version.into(),
                },
            )]);
            assert!(check_resolution_metadata(&exports, &[]).is_err());
        }
        let exports = BTreeMap::from([(
            "filesystem".into(),
            AbilityExport {
                version: "1.2.3-beta.1+source".into(),
            },
        )]);
        check_resolution_metadata(&exports, &[]).unwrap();
        assert!(check_resolution_metadata(&exports, &[source().into(), source().into()]).is_err());
    }

    #[test]
    fn candidate_matching_keeps_ability_and_package_versions_independent() {
        let mut candidate = source();
        candidate.version = "8.0.0".into();
        let exports = BTreeMap::from([(
            "filesystem".into(),
            AbilityExport {
                version: "1.4.0".into(),
            },
        )]);
        let mut request = ModuleDependency::Ranged {
            package: source(),
            abilities: BTreeMap::from([("filesystem".into(), "^1.2".into())]),
            package_version: None,
        };

        assert!(
            request
                .accepts(&candidate, &candidate.version, &exports)
                .unwrap()
        );
        assert!(
            !request
                .accepts(&candidate, &candidate.version, &BTreeMap::new())
                .unwrap()
        );
        if let ModuleDependency::Ranged {
            package_version, ..
        } = &mut request
        {
            *package_version = Some("^7.0".into());
        }
        assert!(
            !request
                .accepts(&candidate, &candidate.version, &exports)
                .unwrap()
        );
        let mut alternative = source();
        alternative.name = "another-provider".into();
        assert!(
            !request
                .accepts(&alternative, &alternative.version, &exports)
                .unwrap()
        );
    }

    #[test]
    fn package_only_ranges_work_but_mixed_duplicate_package_edges_are_rejected() {
        let request = ModuleDependency::Ranged {
            package: source(),
            abilities: BTreeMap::new(),
            package_version: Some("^7.0".into()),
        };
        request.check().unwrap();
        request.requirement().unwrap().check().unwrap();
        assert!(
            request
                .accepts(&source(), "7.0.0", &BTreeMap::new())
                .unwrap()
        );
        assert!(check_resolution_metadata(&BTreeMap::new(), &[source().into(), request]).is_err());
    }

    #[test]
    fn requirement_limits_and_prerelease_matching_are_explicit() {
        let exports = BTreeMap::from([(
            "filesystem".into(),
            AbilityExport {
                version: "1.2.3-beta.2".into(),
            },
        )]);
        let mut request = ModuleDependency::Ranged {
            package: source(),
            abilities: BTreeMap::from([("filesystem".into(), "^1.2.3".into())]),
            package_version: None,
        };

        assert!(!request.accepts(&source(), "7.0.0", &exports).unwrap());
        if let ModuleDependency::Ranged { abilities, .. } = &mut request {
            abilities.insert("filesystem".into(), ">=1.2.3-beta.1, <2.0.0".into());
        }
        assert!(request.accepts(&source(), "7.0.0", &exports).unwrap());
        check_requirement(&vec![">=1.0.0"; 32].join(", ")).unwrap();
        assert!(check_requirement(&vec![">=1.0.0"; 33].join(", ")).is_err());
        assert!(check_requirement(&format!("{}>=1.0.0", " ".repeat(4096))).is_err());
        let oversized = BTreeMap::from([(
            "filesystem".into(),
            AbilityExport {
                version: format!("1.2.3+{}", "a".repeat(128)),
            },
        )]);
        assert!(check_resolution_metadata(&oversized, &[]).is_err());
    }
}
