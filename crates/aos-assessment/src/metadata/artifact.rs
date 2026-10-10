//! Exact artifact inventory projection from authenticated package declarations.
//!
//! Hosts authenticate the enclosing publication and primary output hash.
//! Declared components preserve unknown binary composition and dependency coverage.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;

use super::PackageScanPublicationV1;
use crate::definition::PackageScanDefinitionV1;
use crate::scan_inventory::{
    ComponentInstance, InventoryRelationship, InventorySubject, RelationshipKind,
    SCAN_INVENTORY_V1, ScanInventoryV1, SubjectKind,
};
use crate::security::{CoverageState, DependencyCoverage};
use crate::validation::text;

/// Binds an authenticated package declaration to its exact primary output.
#[derive(Clone, Debug)]
pub struct ArtifactScanBinding {
    /// Closed declaration authenticated by the publisher's signed catalog.
    pub declaration: PackageScanPublicationV1,
    /// Exact authenticated primary output NAR byte identity.
    pub artifact_digest: Sha256Digest,
}

/// Projects signed package declarations onto exact published primary outputs.
///
/// The host supplies a portable publisher incarnation. Artifact identity enters
/// every subject reference. Distinct definition revisions for retained versions
/// remain separate, while identical exact owners share one definition object.
/// Declared containment establishes neither analyzed binary composition nor
/// complete shipped dependencies; patches and configuration remain unknown.
///
/// # Errors
/// Returns an error for invalid or conflicting declarations, repeated published
/// coordinates, invalid publisher scope or exceeded inventory bounds.
pub fn published_artifact_inventory(
    bindings: &[ArtifactScanBinding],
    coordinate_prefix: &str,
) -> Result<(ScanInventoryV1, Vec<PackageScanDefinitionV1>)> {
    text(coordinate_prefix, 512, "admitted publisher coordinate")?;
    if bindings.is_empty()
        || bindings.len() > 10_000
        || coordinate_prefix.starts_with('/')
        || coordinate_prefix.ends_with('/')
        || coordinate_prefix.contains("://")
    {
        bail!("published assessment scope exceeds its output or portable coordinate bounds");
    }
    let mut definitions = BTreeMap::new();
    let mut coordinates = BTreeSet::new();
    let mut subjects = Vec::new();
    let mut components = Vec::new();
    let mut relationships = Vec::new();
    for binding in bindings {
        let declaration = &binding.declaration;
        declaration.validate()?;
        if !coordinates.insert((
            &declaration.package_name,
            &declaration.version,
            &declaration.platform,
        )) {
            bail!("published assessment inventory repeats an immutable output coordinate");
        }
        for definition in &declaration.definitions {
            let digest = definition.digest()?;
            if let Some(previous) = definitions.insert(digest, definition.clone())
                && previous != *definition
            {
                bail!("published definitions conflict under one content identity");
            }
        }
        let selected = declaration
            .definitions
            .iter()
            .find(|definition| {
                definition
                    .members
                    .binary_search(&declaration.member_id)
                    .is_ok()
            })
            .context("published selected member is absent")?;
        let owner = declaration.owner_definition()?;
        let owner_digest = owner.digest()?;
        let subject_ref = Sha256Digest::of_canonical(
            "aos.published-artifact-subject/v1",
            &(
                coordinate_prefix,
                &declaration.package_name,
                &declaration.version,
                &declaration.platform,
                "out",
                binding.artifact_digest,
            ),
        )?
        .to_string();
        let mut component_digests = Vec::new();
        for declared in &owner.components {
            let component_ref = Sha256Digest::of_canonical(
                "aos.published-artifact-component/v1",
                &(&subject_ref, &declared.component_id, owner_digest),
            )?
            .to_string();
            let component = ComponentInstance {
                component_ref: component_ref.clone(),
                component_id: declared.component_id.clone(),
                subject_ref: subject_ref.clone(),
                current: declared.current.clone(),
                scan_definition_digest: owner_digest,
                security: declared.security.clone(),
                artifact_digest: Some(binding.artifact_digest),
                source_content_digest: None,
                configuration_digest: None,
                patch_set_digest: None,
            };
            component_digests.push(component.digest()?);
            components.push(component);
            relationships.push(InventoryRelationship {
                from_ref: subject_ref.clone(),
                kind: RelationshipKind::Contains,
                to_ref: component_ref,
            });
        }
        subjects.push(InventorySubject {
            subject_ref,
            package_coordinate: format!("{coordinate_prefix}/{}", declaration.package_name),
            version: declaration.version.clone(),
            platform: declaration.platform.clone(),
            output: "out".into(),
            kind: SubjectKind::PackageArtifact,
            artifact_digest: Some(binding.artifact_digest),
            scan_definition_digest: selected.digest()?,
            component_inventory_digest: Sha256Digest::of_canonical(
                "aos.published-declared-components/v1",
                &(
                    declaration.digest()?,
                    binding.artifact_digest,
                    component_digests,
                ),
            )?,
            source_content_digest: None,
            member_refs: vec![],
        });
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
            basis: "Authenticated declarations do not establish binary composition or shipped dependency coverage.".into(),
        },
    };
    inventory.validate()?;
    Ok((inventory, definitions.into_values().collect()))
}
