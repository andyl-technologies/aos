//! Portable source subjects bound to explicit evaluated package versions.
//!
//! Source packages carry exact evaluated coordinates, platform and source
//! identity. Alias and generated definitions use their declared owner member;
//! they never borrow an owner's version to invent their own package version.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::PackageAssessmentInventoryV1;
use crate::identity::MemberId;
use crate::scan_inventory::{
    ComponentInstance, InventoryRelationship, InventorySubject, RelationshipKind,
    SCAN_INVENTORY_V1, ScanInventoryV1, SubjectKind,
};
use crate::security::{CoverageState, DependencyCoverage};
use crate::validation::text;

/// Binds one source package to the version and platform actually evaluated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourcePackageBindingV1 {
    /// Exact declared output/member in the maintenance inventory.
    pub member: MemberId,
    /// Evaluated AOS package version, independent of upstream owner versions.
    pub version: String,
    /// Exact target platform evaluated by the source inventory adapter.
    pub platform: String,
}

impl PackageAssessmentInventoryV1 {
    /// Projects source subjects from explicit evaluated package and content bindings.
    ///
    /// The adapter supplies a publisher-scoped coordinate prefix and an exact
    /// source content identity, such as a verified archive or repository tree.
    /// Absolute checkout paths and Git implementation details are absent. This
    /// source projection leaves dependency coverage unknown until authenticated
    /// artifact/SBOM evidence establishes what was actually shipped.
    ///
    /// # Errors
    /// Returns an error for missing, extra, duplicate or invalid bindings,
    /// mismatched ownership, malformed metadata or portable inventory limits.
    pub fn source_inventory(
        &self,
        bindings: &[SourcePackageBindingV1],
        coordinate_prefix: &str,
        source_content_digest: Sha256Digest,
    ) -> Result<ScanInventoryV1> {
        text(coordinate_prefix, 768, "source package coordinate prefix")?;
        if coordinate_prefix.ends_with('/') || bindings.len() > 10_000 {
            bail!("source package scope exceeds its coordinate or member limits");
        }
        let definitions = self.definitions()?;
        let mut indexed = BTreeMap::new();
        for binding in bindings {
            text(&binding.version, 256, "evaluated source package version")?;
            text(&binding.platform, 128, "evaluated source package platform")?;
            if indexed.insert(&binding.member, binding).is_some() {
                bail!("source package bindings repeat an evaluated member");
            }
        }
        let expected = definitions
            .iter()
            .flat_map(|definition| &definition.members)
            .collect::<std::collections::BTreeSet<_>>();
        if !expected.iter().copied().eq(indexed.keys().copied()) {
            bail!("evaluated source package bindings differ from declared members");
        }

        let mut subjects = Vec::new();
        let mut components = Vec::new();
        let mut relationships = Vec::new();
        for definition in definitions {
            let definition_digest = definition.digest()?;
            for member in &definition.members {
                let binding = indexed
                    .get(member)
                    .context("evaluated source member is absent")?;
                let subject_ref =
                    reference("subject", member, &binding.platform, coordinate_prefix)?;
                let mut subject_components = Vec::new();
                for declared in &definition.components {
                    let component_ref = format!(
                        "component-{}",
                        Sha256Digest::of_canonical(
                            "aos.source-component-reference/v1",
                            &(&subject_ref, &declared.component_id),
                        )?
                    );
                    let component = ComponentInstance {
                        component_ref: component_ref.clone(),
                        component_id: declared.component_id.clone(),
                        subject_ref: subject_ref.clone(),
                        current: declared.current.clone(),
                        scan_definition_digest: definition_digest,
                        security: declared.security.clone(),
                        artifact_digest: None,
                        source_content_digest: Some(source_content_digest),
                        configuration_digest: None,
                        patch_set_digest: None,
                    };
                    subject_components.push(component.digest()?);
                    components.push(component);
                    relationships.push(InventoryRelationship {
                        from_ref: subject_ref.clone(),
                        kind: RelationshipKind::Contains,
                        to_ref: component_ref,
                    });
                }
                let member_refs = if let Some(owner) = &definition.owner_ref {
                    let owner_binding = indexed
                        .get(&owner.member_id)
                        .context("evaluated source owner is absent")?;
                    if owner_binding.platform != binding.platform {
                        bail!("source alias owner was evaluated for a different platform");
                    }
                    let owner_ref = reference(
                        "subject",
                        &owner.member_id,
                        &owner_binding.platform,
                        coordinate_prefix,
                    )?;
                    relationships.push(InventoryRelationship {
                        from_ref: subject_ref.clone(),
                        kind: RelationshipKind::Contains,
                        to_ref: owner_ref.clone(),
                    });
                    vec![owner_ref]
                } else {
                    vec![]
                };
                subjects.push(InventorySubject {
                    subject_ref,
                    package_coordinate: format!("{coordinate_prefix}/{member}"),
                    version: binding.version.clone(),
                    platform: binding.platform.clone(),
                    output: "source".into(),
                    kind: SubjectKind::Source,
                    artifact_digest: None,
                    scan_definition_digest: definition_digest,
                    component_inventory_digest: Sha256Digest::of_canonical(
                        "aos.source-component-inventory/v1",
                        &(&subject_components, &member_refs),
                    )?,
                    source_content_digest: Some(source_content_digest),
                    member_refs,
                });
            }
        }
        subjects.sort_by(|left, right| left.subject_ref.cmp(&right.subject_ref));
        components.sort_by(|left, right| left.component_ref.cmp(&right.component_ref));
        relationships.sort();
        let inventory = ScanInventoryV1 {
            schema: SCAN_INVENTORY_V1.into(),
            subjects,
            components,
            relationships,
            coverage: DependencyCoverage {
                state: CoverageState::Unknown,
                basis: "Source metadata does not establish shipped dependency coverage.".into(),
            },
        };
        inventory.validate()?;
        Ok(inventory)
    }
}

fn reference(kind: &str, member: &MemberId, platform: &str, prefix: &str) -> Result<String> {
    Ok(format!(
        "{kind}-{}",
        Sha256Digest::of_canonical(
            "aos.source-subject-reference/v1",
            &(member, platform, prefix),
        )?
    ))
}
