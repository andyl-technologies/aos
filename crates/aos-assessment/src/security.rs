//! Declarative advisory identities and dependency-coverage claims.
//!
//! Package-authored records contain product identities and supported source
//! mappings, never credentials, network origins, or executable scanner hooks.
//! A component may declare an explicit unmapped identity:
//!
//! ```json
//! {"kind":"unmapped","reason":"identity-unmapped","explanation":"Mapping requires review"}
//! ```

use std::str::FromStr;

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::validation::{sorted, text};

/// Identifies an upstream product without relying on the AOS package name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SecurityIdentity {
    /// Declares a reviewed CPE product association.
    Cpe {
        /// CPE part: application, operating system, or hardware.
        part: String,
        /// Explicit upstream vendor; wildcard identities are not reviewed mappings.
        vendor: String,
        /// Explicit upstream product.
        product: String,
        /// Optional constrained product edition.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        edition: Option<String>,
        /// Optional constrained target software environment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_software: Option<String>,
        /// Optional constrained hardware platform.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_hardware: Option<String>,
    },
    /// Uses an exact advisory ecosystem and upstream package name.
    Ecosystem {
        /// Provider-recognized ecosystem, including its exact spelling.
        ecosystem: String,
        /// Provider-native upstream package name.
        name: String,
    },
    /// Binds an upstream repository and immutable revision.
    Git {
        /// Canonical credential-free HTTPS upstream repository.
        repository: String,
        /// Exact full hexadecimal commit identity.
        commit: String,
    },
    /// Preserves the parsed Package URL type and qualifiers.
    Purl {
        /// Canonical Package URL; no ecosystem is inferred for generic/Nix types.
        value: String,
    },
    /// Makes missing advisory identity visible instead of guessing by name.
    Unmapped {
        /// Stable explanation code.
        reason: String,
        /// Bounded package-maintainer explanation.
        explanation: String,
    },
}

impl SecurityIdentity {
    /// Validates identity structure without establishing publisher authority.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid, oversized, credential-bearing, ambiguous,
    /// or noncanonical product identities.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Ecosystem { ecosystem, name } => {
                text(ecosystem, 128, "ecosystem")?;
                text(name, 1024, "upstream package name")?;
            }
            Self::Purl { value } => {
                text(value, 2048, "Package URL")?;
                let parsed = packageurl::PackageUrl::from_str(value)
                    .context("invalid assessment Package URL")?;
                if parsed.to_string() != *value {
                    bail!("assessment Package URL is not canonical");
                }
            }
            Self::Git { repository, commit } => {
                text(repository, 2048, "Git repository")?;
                let url = url::Url::parse(repository).context("invalid upstream Git URL")?;
                if url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || url.as_str() != repository
                {
                    bail!("upstream Git identity requires canonical credential-free HTTPS");
                }
                if !matches!(commit.len(), 40 | 64)
                    || !commit
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    bail!("upstream Git identity requires a full lowercase commit");
                }
            }
            Self::Cpe {
                part,
                vendor,
                product,
                edition,
                target_software,
                target_hardware,
            } => {
                if !matches!(part.as_str(), "a" | "o" | "h") {
                    bail!("invalid CPE product part");
                }
                for value in [
                    Some(vendor),
                    Some(product),
                    edition.as_ref(),
                    target_software.as_ref(),
                    target_hardware.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    text(value, 256, "CPE product field")?;
                    if value == "-" || value.contains(['*', '?', ':', '\\']) {
                        bail!("CPE mapping requires explicit unambiguous product fields");
                    }
                }
            }
            Self::Unmapped {
                reason,
                explanation,
            } => {
                text(reason, 128, "unmapped reason")?;
                text(explanation, 4096, "unmapped explanation")?;
            }
        }
        Ok(())
    }
}

/// Selects supported ordering for advisory applicability, separately from updates.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdvisoryVersionScheme {
    /// Compares Semantic Versioning precedence.
    Semver,
    /// Compares dotted numeric components with zero padding.
    DottedNumeric,
    /// Requires an admitted ecosystem-specific comparator profile.
    Ecosystem,
    /// Requires explicit immutable commit/ancestry evidence.
    Git,
    /// Reports unsupported comparison without lexical fallback.
    Unsupported,
}

/// Classifies the established coverage of an inventory or source question.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageState {
    /// Establishes complete coverage under the named proof/profile.
    Complete,
    /// Contains useful evidence without a complete proof.
    Partial,
    /// Cannot establish the requested scope.
    Unknown,
}

/// Preserves dependency-coverage state separately from an empty component list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DependencyCoverage {
    /// Established or declared completeness of the relevant inventory.
    pub state: CoverageState,
    /// Explicit evidence basis or missing-coverage reason.
    pub basis: String,
}

/// Selects one installed advisory source and its exact product mapping.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisorySourceMapping {
    /// Installed provider profile: OSV, NVD, or a reviewed upstream profile.
    pub provider: String,
    /// Optional exact project identity under that profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

/// Declares a component's security identity and scan semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecurityDeclaration {
    /// Strictly sorted identities, or an explicit unmapped identity.
    pub identities: Vec<SecurityIdentity>,
    /// Strictly sorted installed source mappings; an empty set establishes no coverage.
    pub advisory_sources: Vec<AdvisorySourceMapping>,
    /// Applicability ordering independent of candidate release ordering.
    pub version_scheme: AdvisoryVersionScheme,
    /// Declared coverage, subsequently checked against build/inventory evidence.
    pub dependency_coverage: DependencyCoverage,
    /// Exact reviewed statements; their digests alone grant no authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disposition_refs: Vec<Sha256Digest>,
}

impl SecurityDeclaration {
    /// Validates the closed security declaration and deterministic set ordering.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/oversized identities, invalid mappings,
    /// duplicate/unsorted sets, or an invalid coverage explanation.
    pub fn validate(&self) -> Result<()> {
        if self.identities.is_empty()
            || self.identities.len() > 32
            || self.advisory_sources.len() > 16
            || self.disposition_refs.len() > 128
        {
            bail!("invalid security declaration scope");
        }
        sorted(&self.identities, "security identities")?;
        sorted(&self.advisory_sources, "advisory sources")?;
        sorted(&self.disposition_refs, "disposition references")?;
        text(
            &self.dependency_coverage.basis,
            4096,
            "dependency coverage basis",
        )?;

        for identity in &self.identities {
            identity.validate()?;
        }
        for source in &self.advisory_sources {
            text(&source.provider, 128, "advisory provider")?;
            if let Some(project) = &source.project {
                text(project, 1024, "advisory project")?;
            }
        }
        Ok(())
    }
}
