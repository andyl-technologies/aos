//! Closed package-security sidecars and evaluation-only inventory projection.
//!
//! The new metadata transport keeps the original maintenance inventory intact.
//! Scan definitions are normalized separately, then authenticated by publication.
//!
//! ```json
//! {"schema":"aos.package-assessment-metadata/v1","unitId":"example-1","components":{}}
//! ```

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::definition::{
    PACKAGE_SCAN_DEFINITION_V1, PackageScanDefinitionV1, ScanComponent, ScanDiscovery, ScanOwnerRef,
};
use crate::identity::{ComponentId, UnitId};
use crate::inventory::MaintenanceInventoryV1;
use crate::security::SecurityDeclaration;
use crate::time::Timestamp;
use crate::validation::{DOCUMENT_LIMITS, decode};

mod publication;
mod source;

pub use publication::{PACKAGE_SCAN_PUBLICATION_V1, PackageScanPublicationV1};
pub use source::SourcePackageBindingV1;

/// Identifies a package's security sidecar without changing maintenance v1.
pub const PACKAGE_ASSESSMENT_METADATA_V1: &str = "aos.package-assessment-metadata/v1";

/// Identifies evaluation-only maintenance/security inventory export.
pub const PACKAGE_ASSESSMENT_INVENTORY_V1: &str = "aos.package-assessment-inventory/v1";

/// Associates declarative security policy with one existing update unit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageAssessmentMetadataV1 {
    /// Exact sidecar schema discriminator.
    pub schema: String,
    /// Exact maintenance unit; names cannot supply automatic CVE mappings.
    pub unit_id: UnitId,
    /// Complete explicit security declarations for that unit's components.
    pub components: BTreeMap<ComponentId, SecurityDeclaration>,
}

impl PackageAssessmentMetadataV1 {
    /// Validates bounded source declarations independently from source execution.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schemas, excessive scope or invalid
    /// identity, source, comparator and coverage declarations.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_ASSESSMENT_METADATA_V1 || self.components.len() > 128 {
            bail!("unsupported or excessive package assessment metadata");
        }
        for security in self.components.values() {
            security.validate()?;
        }
        Ok(())
    }

    /// Decodes one exact bounded security sidecar.
    ///
    /// # Errors
    ///
    /// Returns an error for ambiguous/oversized JSON, null optional members,
    /// incompatible schemas or invalid security declarations.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let metadata: Self = decode(bytes, "package assessment metadata")?;
        metadata.validate()?;
        Ok(metadata)
    }
}

/// Preserves legacy maintenance metadata alongside closed security sidecars.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageAssessmentInventoryV1 {
    /// Exact transport schema discriminator.
    pub schema: String,
    /// Unchanged legacy inventory, including its existing optional-field rules.
    pub maintenance_inventory: MaintenanceInventoryV1,
    /// One complete security sidecar per unit, ordered by unit identity.
    pub security_declarations: Vec<PackageAssessmentMetadataV1>,
}

impl PackageAssessmentInventoryV1 {
    /// Decodes the new export while preserving legacy null-field compatibility.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate/unknown fields, resource bounds, invalid
    /// source declarations, missing/mismatched units or incompatible versions.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Value = DOCUMENT_LIMITS.decode(bytes, "package assessment inventory")?;
        let declarations = value
            .get("securityDeclarations")
            .and_then(Value::as_array)
            .context("assessment inventory lacks security sidecars")?;
        for declaration in declarations {
            PackageAssessmentMetadataV1::from_slice(&serde_json::to_vec(declaration)?)?;
        }
        let inventory: Self = serde_json::from_value(value)?;
        inventory.validate()?;
        Ok(inventory)
    }

    /// Validates exact unit/component correspondence without inferring identities.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid maintenance inventory, duplicate/missing unit
    /// sidecars, incompatible schemas or security scope outside its owning unit.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_ASSESSMENT_INVENTORY_V1
            || self.security_declarations.len() != self.maintenance_inventory.units.len()
        {
            bail!("assessment inventory requires exact security/maintenance correspondence");
        }
        self.maintenance_inventory.validate()?;
        if self
            .security_declarations
            .windows(2)
            .any(|pair| pair[0].unit_id >= pair[1].unit_id)
        {
            bail!("assessment security units must be sorted and unique");
        }
        for (unit, sidecar) in self
            .maintenance_inventory
            .units
            .iter()
            .zip(&self.security_declarations)
        {
            sidecar.validate()?;
            if unit.unit_id != sidecar.unit_id
                || !unit.components.keys().eq(sidecar.components.keys())
            {
                bail!("assessment security sidecar differs from its owning maintenance unit");
            }
        }
        Ok(())
    }

    /// Projects closed immutable definitions with exact generated/alias ownership.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, unavailable/cyclic owner definitions,
    /// invalid review times, incompatible ownership or definition resource bounds.
    pub fn definitions(&self) -> Result<Vec<PackageScanDefinitionV1>> {
        self.validate()?;
        let mut resolved = BTreeMap::<UnitId, PackageScanDefinitionV1>::new();
        let mut pending = self
            .maintenance_inventory
            .units
            .iter()
            .zip(&self.security_declarations)
            .map(|(unit, sidecar)| (&unit.unit_id, (unit, sidecar)))
            .collect::<BTreeMap<_, _>>();
        while !pending.is_empty() {
            let ready = pending
                .iter()
                .filter_map(|(id, (unit, _))| {
                    (unit
                        .owner_unit
                        .as_ref()
                        .is_none_or(|owner| resolved.contains_key(owner)))
                    .then_some(*id)
                })
                .cloned()
                .collect::<Vec<_>>();
            if ready.is_empty() {
                bail!("assessment definition ownership is cyclic or unavailable");
            }
            for id in ready {
                let (unit, sidecar) = pending
                    .remove(&id)
                    .context("assessment definition disappeared during projection")?;
                let owner_ref = if let Some(owner_id) = &unit.owner_unit {
                    let owner = resolved
                        .get(owner_id)
                        .context("assessment owner definition is unavailable")?;
                    let member_id = unit
                        .owner_member
                        .as_ref()
                        .context("assessment owner member is absent")?;
                    if owner.members.binary_search(member_id).is_err() {
                        bail!("assessment owner does not own the declared member");
                    }
                    Some(ScanOwnerRef {
                        unit_id: owner_id.clone(),
                        member_id: member_id.clone(),
                        definition_digest: owner.digest()?,
                    })
                } else {
                    None
                };
                let definition = PackageScanDefinitionV1 {
                    schema: PACKAGE_SCAN_DEFINITION_V1.into(),
                    unit_id: unit.unit_id.clone(),
                    family: unit.family.clone(),
                    stream: unit.stream.clone(),
                    members: unit.members.clone(),
                    classification: unit.classification,
                    lifecycle: unit.policy.lifecycle,
                    components: unit
                        .components
                        .iter()
                        .map(|(id, component)| {
                            Ok(ScanComponent {
                                component_id: id.clone(),
                                current: component.current.clone(),
                                discovery: ScanDiscovery {
                                    primary: component.primary.clone(),
                                    advisors: component.advisors.clone(),
                                },
                                release_policy: component.release_policy.clone(),
                                security: sidecar
                                    .components
                                    .get(id)
                                    .context("assessment component security is missing")?
                                    .clone(),
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                    version_projection: unit
                        .package
                        .as_ref()
                        .map(|package| package.version_projection.clone()),
                    owner_ref,
                    reason: unit.reason.clone(),
                    review_after: unit
                        .review_after
                        .as_ref()
                        .map(|review| {
                            Timestamp::parse(&if review.len() == 10 {
                                format!("{review}T00:00:00Z")
                            } else {
                                review.clone()
                            })
                        })
                        .transpose()?,
                    cohort: unit.cohort.clone(),
                    metadata_origins: vec![unit.owner.clone()],
                };
                definition.validate()?;
                resolved.insert(id, definition);
            }
        }
        Ok(resolved.into_values().collect())
    }
}
