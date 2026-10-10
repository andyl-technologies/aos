//! Publication availability without invented inventory or security identities.
//!
//! `aos.assessment-publication-status/v1` distinguishes a missing publication,
//! an unavailable projection and authenticated outputs without scan declarations.
//! Complete declarations establish assessment availability, never a clean result.
//! Continuations bind the exact publication commitment and resource incarnation.

use anyhow::{Result, bail, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::{Sha256Digest, canonical, limits::JsonLimits};
use serde::{Deserialize, Serialize};

use crate::validation::{decode, text};

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 262_144,
    max_depth: 16,
    max_items: 16_384,
    max_string_bytes: 4096,
};

/// Selects a bounded page of primary outputs lacking scan declarations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PublicationQueryV1 {
    /// Exact query discriminator.
    pub schema: String,
    /// Maximum complete output records, between one and one hundred.
    pub limit: u32,
    /// Exclusive output commitment from the preceding page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_output: Option<Sha256Digest>,
    /// Exact publication commitment required for continuation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_digest: Option<Sha256Digest>,
    /// Non-reusable resource scope required for continuation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<String>,
}

impl PublicationQueryV1 {
    /// Decodes and validates one closed publication selector.
    ///
    /// # Errors
    /// Returns an error for excessive input, unknown fields or unbound cursors.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let query: Self = decode(bytes, "assessment publication query")?;
        ensure!(
            query.schema == "aos.assessment-publication-query/v1"
                && (1..=100).contains(&query.limit),
            "invalid assessment publication query"
        );
        if let Some(scope) = &query.resource_scope {
            text(scope, 128, "publication resource scope")?;
        }
        ensure!(
            query.after_output.is_none()
                || (query.publication_digest.is_some() && query.resource_scope.is_some()),
            "publication continuation lacks its exact scope or commitment"
        );
        Ok(query)
    }
}

/// Identifies the independently authenticated latest logical release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PublicationRelease {
    /// Exact published release tag.
    pub release: String,
    /// Exact catalog source commit.
    pub source_commit: String,
    /// Exact tag identity authenticated by the release indexer.
    pub verified_tag_oid: String,
}

impl PublicationRelease {
    fn validate(&self) -> Result<()> {
        text(&self.release, 255, "publication release")?;
        text(&self.source_commit, 128, "publication source commit")?;
        text(&self.verified_tag_oid, 128, "publication verified tag")
    }
}

/// Commits exact catalog bytes and the complete verified artifact snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PublicationCommitment {
    /// Exact authenticated release context.
    pub release: PublicationRelease,
    /// Digest of the retained catalog bytes, without reinterpretation.
    pub catalog_digest: Sha256Digest,
    /// Exact complete artifact snapshot identity.
    pub snapshot_id: String,
    /// Digest of the authenticated artifact snapshot manifest.
    pub manifest_digest: Sha256Digest,
}

impl PublicationCommitment {
    /// Computes a publication commitment bound to a resource incarnation.
    ///
    /// # Errors
    /// Returns an error for invalid context or canonical encoding failure.
    pub fn digest(&self, resource_scope: &str) -> Result<Sha256Digest> {
        self.release.validate()?;
        text(&self.snapshot_id, 128, "publication snapshot")?;
        text(resource_scope, 128, "publication resource scope")?;
        Sha256Digest::of_canonical(
            "aos.assessment-publication-context/v1",
            &(resource_scope, self),
        )
    }
}

/// Identifies a primary output whose publisher supplied no scan declaration.
///
/// These are publication coordinates, not inferred vulnerability identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnsupportedPublicationOutput {
    /// Commitment to the exact publication and output coordinate.
    pub output_ref: Sha256Digest,
    /// Exact package name in the authenticated catalog.
    pub package_name: String,
    /// Exact published AOS version.
    pub version: String,
    /// Exact published target platform.
    pub platform: String,
    /// Exact primary store path in the complete artifact snapshot.
    pub store_path: String,
}

impl UnsupportedPublicationOutput {
    /// Computes the exact publication-bound output reference.
    ///
    /// # Errors
    /// Returns an error for invalid coordinates or canonical encoding failure.
    pub fn reference(
        publication_digest: Sha256Digest,
        package_name: &str,
        version: &str,
        platform: &str,
        store_path: &str,
    ) -> Result<Sha256Digest> {
        text(package_name, 255, "unsupported publication package")?;
        text(version, 256, "unsupported publication version")?;
        text(platform, 128, "unsupported publication platform")?;
        text(store_path, 4096, "unsupported publication store path")?;
        Sha256Digest::of_canonical(
            "aos.assessment-unsupported-output/v1",
            &(
                publication_digest,
                package_name,
                version,
                platform,
                store_path,
            ),
        )
    }
}

/// Distinguishes publication availability from evidence coverage and findings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum PublicationAvailability {
    /// No authenticated logical release exists in the current database.
    NoPublication,
    /// The latest release lacks a bounded complete authenticated projection.
    AwaitingProjection {
        /// Exact latest release that needs its catalog and artifact snapshot.
        release: PublicationRelease,
    },
    /// Retained projection validation failed; no older inventory is substituted.
    InvalidProjection {
        /// Exact latest release whose projection cannot be assessed.
        release: PublicationRelease,
    },
    /// The authenticated catalog contains no declared scan inventory.
    Unassessable {
        /// Exact authenticated publication, independent of assessment admission.
        publication: PublicationCommitment,
        /// Total primary outputs without declarations, including later pages.
        unsupported_count: u32,
    },
    /// The authenticated catalog has an exact declared scan inventory.
    Ready {
        /// Exact authenticated publication, independent of assessment admission.
        publication: PublicationCommitment,
        /// Exact declared inventory, including its explicit coverage basis.
        inventory_digest: Sha256Digest,
        /// Number of authenticated primary outputs with scan declarations.
        declared_outputs: u32,
        /// Total primary outputs without declarations, including later pages.
        unsupported_count: u32,
        /// Current activation revision, absent while awaiting inventory activation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_inventory_revision: Option<u64>,
    },
}

/// Reports publication availability and a complete bounded unsupported-output page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PublicationStatusV1 {
    /// Exact response discriminator.
    pub schema: String,
    /// Non-reusable resource incarnation independently authorized by the service.
    pub resource_scope: String,
    /// Database observation time for this publication projection.
    pub as_of: Timestamp,
    /// Publication state that makes no vulnerability or update-status assertion.
    pub availability: PublicationAvailability,
    /// Exact publication commitment when a complete projection is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_digest: Option<Sha256Digest>,
    /// Primary outputs lacking declarations in strictly increasing reference order.
    pub unsupported_outputs: Vec<UnsupportedPublicationOutput>,
    /// Exact last output reference when more complete records remain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_output: Option<Sha256Digest>,
}

impl PublicationStatusV1 {
    /// Encodes the complete closed projection without dropping output records.
    ///
    /// # Errors
    /// Returns an error for inconsistent commitments, counts, ordering or bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        LIMITS.check_value(&value, "assessment publication status")?;
        let bytes = canonical::to_vec(&value)?;
        ensure!(
            bytes.len() <= LIMITS.max_bytes,
            "publication status exceeds its response bound"
        );
        Ok(bytes)
    }

    /// Decodes and checks the exact publication and output associations.
    ///
    /// # Errors
    /// Returns an error for ambiguous, unknown, excessive or inconsistent input.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "assessment publication status")?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-publication-status/v1"
                && self.unsupported_outputs.len() <= 100,
            "invalid publication status envelope"
        );
        text(&self.resource_scope, 128, "publication resource scope")?;
        let (publication, count) = match &self.availability {
            PublicationAvailability::NoPublication => (None, 0),
            PublicationAvailability::AwaitingProjection { release }
            | PublicationAvailability::InvalidProjection { release } => {
                release.validate()?;
                (None, 0)
            }
            PublicationAvailability::Unassessable {
                publication,
                unsupported_count,
            } => (Some(publication), *unsupported_count),
            PublicationAvailability::Ready {
                publication,
                declared_outputs,
                unsupported_count,
                active_inventory_revision,
                ..
            } => {
                ensure!(
                    *declared_outputs > 0
                        && *declared_outputs <= 10_000
                        && u64::from(*declared_outputs) + u64::from(*unsupported_count) <= 10_000
                        && active_inventory_revision
                            .is_none_or(|value| (1..=9_007_199_254_740_991).contains(&value)),
                    "invalid declared publication coverage"
                );
                (Some(publication), *unsupported_count)
            }
        };
        ensure!(
            count <= 10_000 && self.unsupported_outputs.len() <= count as usize,
            "publication output page exceeds its declared total"
        );
        let digest = publication
            .map(|value| value.digest(&self.resource_scope))
            .transpose()?;
        ensure!(
            self.publication_digest == digest,
            "publication context commitment differs"
        );
        for output in &self.unsupported_outputs {
            let digest =
                digest.ok_or_else(|| anyhow::anyhow!("output lacks publication custody"))?;
            ensure!(
                output.output_ref
                    == UnsupportedPublicationOutput::reference(
                        digest,
                        &output.package_name,
                        &output.version,
                        &output.platform,
                        &output.store_path
                    )?,
                "unsupported output differs from its publication commitment"
            );
        }
        ensure!(
            self.unsupported_outputs
                .windows(2)
                .all(|pair| pair[0].output_ref < pair[1].output_ref),
            "unsupported outputs are not sorted and unique"
        );
        if let Some(next) = self.next_output
            && (self
                .unsupported_outputs
                .last()
                .is_none_or(|output| output.output_ref != next)
                || self.unsupported_outputs.len() >= count as usize)
        {
            bail!("publication continuation differs from its complete output page");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context as _;

    fn fixture() -> Result<PublicationStatusV1> {
        let publication = PublicationCommitment {
            release: PublicationRelease {
                release: "1.0.0".into(),
                source_commit: "fixture-commit".into(),
                verified_tag_oid: "fixture-authenticated-tag".into(),
            },
            catalog_digest: Sha256Digest::of_bytes("catalog"),
            snapshot_id: "fixture-complete-snapshot".into(),
            manifest_digest: Sha256Digest::of_bytes("manifest"),
        };
        let scope = "fixture-registry-incarnation";
        let digest = publication.digest(scope)?;
        let package_name = "fixture";
        let version = "1.2.0";
        let platform = "x86_64-linux";
        let store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture-1.2.0";
        Ok(PublicationStatusV1 {
            schema: "aos.assessment-publication-status/v1".into(),
            resource_scope: scope.into(),
            as_of: Timestamp::from_unix_seconds(100)?,
            availability: PublicationAvailability::Unassessable {
                publication,
                unsupported_count: 2,
            },
            publication_digest: Some(digest),
            unsupported_outputs: vec![UnsupportedPublicationOutput {
                output_ref: UnsupportedPublicationOutput::reference(
                    digest,
                    package_name,
                    version,
                    platform,
                    store_path,
                )?,
                package_name: package_name.into(),
                version: version.into(),
                platform: platform.into(),
                store_path: store_path.into(),
            }],
            next_output: None,
        })
    }

    #[test]
    fn publication_coordinates_are_bound_without_inferred_scan_identities() -> Result<()> {
        let mut value = fixture()?;
        assert_eq!(PublicationStatusV1::from_slice(&value.to_bytes()?)?, value);
        value.unsupported_outputs[0].version = "1.3.0".into();
        assert!(value.to_bytes().is_err());
        let mut value = fixture()?;
        value.resource_scope = "different-registry-incarnation".into();
        assert!(value.to_bytes().is_err());
        let mut value = fixture()?;
        value
            .unsupported_outputs
            .push(value.unsupported_outputs[0].clone());
        assert!(value.to_bytes().is_err());
        let mut value = fixture()?;
        value.availability = PublicationAvailability::NoPublication;
        assert!(value.to_bytes().is_err());
        Ok(())
    }

    #[test]
    fn publication_continuations_require_exact_context_and_complete_page_edges() -> Result<()> {
        let mut query = PublicationQueryV1 {
            schema: "aos.assessment-publication-query/v1".into(),
            limit: 100,
            after_output: Some(Sha256Digest::of_bytes("position")),
            publication_digest: None,
            resource_scope: None,
        };
        assert!(PublicationQueryV1::from_slice(&serde_json::to_vec(&query)?).is_err());
        query.publication_digest = Some(Sha256Digest::of_bytes("context"));
        assert!(PublicationQueryV1::from_slice(&serde_json::to_vec(&query)?).is_err());
        query.resource_scope = Some("scope".into());
        PublicationQueryV1::from_slice(&serde_json::to_vec(&query)?)?;
        let mut value = fixture()?;
        value.next_output = Some(value.unsupported_outputs[0].output_ref);
        value.to_bytes()?;
        value.next_output = Some(Sha256Digest::of_bytes("different-position"));
        assert!(value.to_bytes().is_err());
        Ok(())
    }

    #[test]
    fn oversized_publication_pages_refuse_instead_of_dropping_coordinates() -> Result<()> {
        let mut value = fixture()?;
        let digest = value
            .publication_digest
            .context("fixture publication digest")?;
        value.unsupported_outputs.clear();
        for index in 0..100 {
            let name = format!("fixture-{index}");
            let path = "p".repeat(4096);
            value
                .unsupported_outputs
                .push(UnsupportedPublicationOutput {
                    output_ref: UnsupportedPublicationOutput::reference(
                        digest,
                        &name,
                        "1.2.0",
                        "x86_64-linux",
                        &path,
                    )?,
                    package_name: name,
                    version: "1.2.0".into(),
                    platform: "x86_64-linux".into(),
                    store_path: path,
                });
        }
        value
            .unsupported_outputs
            .sort_by_key(|output| output.output_ref);
        if let PublicationAvailability::Unassessable {
            unsupported_count, ..
        } = &mut value.availability
        {
            *unsupported_count = 100;
        }
        assert!(value.to_bytes().is_err());
        assert_eq!(value.unsupported_outputs.len(), 100);
        Ok(())
    }
}
