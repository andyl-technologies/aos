//! Closed scan declarations retained inside authenticated package metadata.
//!
//! A publication carries only the selected update unit and its exact owner
//! closure. Provider evidence, assessment status, credentials and scheduling
//! remain independent records owned by the assessment service.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::PackageAssessmentInventoryV1;
use crate::definition::PackageScanDefinitionV1;
use crate::identity::{MemberId, UnitId};
use crate::validation::{decode, digest, text};

/// Identifies a package catalog's immutable scan declaration.
pub const PACKAGE_SCAN_PUBLICATION_V1: &str = "aos.package-scan-publication/v1";

/// Retains the exact scan policy for one published package version and platform.
///
/// The enclosing publication authenticates these bytes. This record does not
/// establish artifact content or dependency completeness; inventory admission
/// must independently bind the published output and signed component evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageScanPublicationV1 {
    /// Exact schema discriminator.
    pub schema: String,
    /// Package name in the enclosing signed catalog.
    pub package_name: String,
    /// Exact published AOS version, independent of owner upstream versions.
    pub version: String,
    /// Exact publication target platform.
    pub platform: String,
    /// Declared maintenance member selected by this package publication.
    pub member_id: MemberId,
    /// Selected definition and complete owner closure, ordered by unit ID.
    pub definitions: Vec<PackageScanDefinitionV1>,
}

impl PackageScanPublicationV1 {
    /// Decodes a bounded, unambiguous declaration without conferring authority.
    ///
    /// # Errors
    /// Returns an error for invalid JSON, unsupported schema, inconsistent
    /// ownership, unrelated definitions, or exceeded declaration limits.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 256 * 1024 {
            bail!("package scan publication exceeds its byte ceiling");
        }
        let publication: Self = decode(bytes, "package scan publication")?;
        publication.validate()?;
        Ok(publication)
    }

    /// Validates exact selected-member ownership and the entire owner closure.
    ///
    /// # Errors
    /// Returns an error for invalid coordinates, missing or ambiguous members,
    /// unbound owners, cycles, repeated units, or unrelated definitions.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_SCAN_PUBLICATION_V1
            || self.definitions.is_empty()
            || self.definitions.len() > 128
        {
            bail!("invalid package scan publication schema or definition scope");
        }
        text(&self.package_name, 96, "published package name")?;
        MemberId::parse(&self.package_name)?;
        text(&self.version, 256, "published package version")?;
        text(&self.platform, 128, "published package platform")?;
        if self
            .definitions
            .windows(2)
            .any(|pair| pair[0].unit_id >= pair[1].unit_id)
        {
            bail!("published scan units must be sorted and unique");
        }

        let mut indexed = BTreeMap::new();
        let mut selected = None;
        for definition in &self.definitions {
            definition.validate()?;
            indexed.insert(&definition.unit_id, definition);
            if definition.members.binary_search(&self.member_id).is_ok()
                && selected.replace(definition).is_some()
            {
                bail!("published maintenance member has ambiguous ownership");
            }
        }
        let mut current = selected.context("published member is absent from its definition")?;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(&current.unit_id) {
                bail!("published scan ownership contains a cycle");
            }
            let Some(owner) = &current.owner_ref else {
                break;
            };
            current = indexed
                .get(&owner.unit_id)
                .copied()
                .context("published owner definition is absent")?;
            if current.digest()? != owner.definition_digest
                || current.members.binary_search(&owner.member_id).is_err()
            {
                bail!("published scan owner differs from its exact admitted definition");
            }
        }
        if visited.len() != indexed.len() {
            bail!("package scan publication includes unrelated definitions");
        }
        Ok(())
    }

    /// Encodes a validated declaration as bounded canonical JSON for a catalog.
    ///
    /// # Errors
    /// Returns an error for invalid declarations, encoding, or byte limits.
    pub fn to_json(&self) -> Result<String> {
        self.validate()?;
        let bytes = aos_contract::canonical::to_vec(self)?;
        if bytes.len() > 256 * 1024 {
            bail!("package scan publication exceeds its byte ceiling");
        }
        String::from_utf8(bytes).context("canonical scan declaration is not UTF-8")
    }

    /// Computes the semantic identity of the immutable publication declaration.
    ///
    /// # Errors
    /// Returns an error for invalid declaration structure or canonical bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.to_json()?;
        digest(PACKAGE_SCAN_PUBLICATION_V1, self)
    }
}

impl PackageAssessmentInventoryV1 {
    /// Selects a bounded package declaration with all and only its exact owners.
    ///
    /// # Errors
    /// Returns an error for invalid evaluated metadata, missing or ambiguous
    /// maintenance ownership, unavailable owners, or invalid publication scope.
    pub fn publication(
        &self,
        member_id: MemberId,
        package_name: String,
        version: String,
        platform: String,
    ) -> Result<PackageScanPublicationV1> {
        let definitions = self.definitions()?;
        let mut selected = definitions
            .iter()
            .filter(|definition| definition.members.binary_search(&member_id).is_ok());
        let root = selected
            .next()
            .context("published member is absent from evaluated metadata")?;
        if selected.next().is_some() {
            bail!("published member has multiple evaluated owners");
        }
        let indexed = definitions
            .iter()
            .map(|definition| (&definition.unit_id, definition))
            .collect::<BTreeMap<_, _>>();
        let mut closure = BTreeMap::<UnitId, PackageScanDefinitionV1>::new();
        let mut current = root;
        loop {
            if closure
                .insert(current.unit_id.clone(), current.clone())
                .is_some()
            {
                bail!("evaluated scan ownership contains a cycle");
            }
            let Some(owner) = &current.owner_ref else {
                break;
            };
            current = indexed
                .get(&owner.unit_id)
                .copied()
                .context("evaluated scan owner is absent")?;
        }
        let publication = PackageScanPublicationV1 {
            schema: PACKAGE_SCAN_PUBLICATION_V1.into(),
            package_name,
            version,
            platform,
            member_id,
            definitions: closure.into_values().collect(),
        };
        publication.to_json()?;
        Ok(publication)
    }
}
