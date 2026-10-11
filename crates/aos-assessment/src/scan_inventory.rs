//! Portable component inventories independent of registry storage and SQL IDs.
//!
//! The closed `aos.scan-inventory/v1` document contains ordered subjects,
//! component instances, relationships, and explicit dependency coverage. A
//! source scan binds source bytes; an artifact scan binds immutable artifacts.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::identity::ComponentId;
use crate::inventory::ComponentVersion;
use crate::security::{DependencyCoverage, SecurityDeclaration};
use crate::validation::{decode, digest, sorted, text};

/// Identifies a portable scan inventory.
pub const SCAN_INVENTORY_V1: &str = "aos.scan-inventory/v1";

/// Identifies the immutable content of a component instance.
pub const COMPONENT_INSTANCE_V1: &str = "aos.component-instance/v1";

/// Selects the immutable subject binding required by an assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectKind {
    /// Assesses one built package output.
    PackageArtifact,
    /// Assesses explicit source bytes without pretending an artifact exists.
    Source,
    /// Assesses exact members of a release.
    Release,
    /// Assesses a built system image's component inventory.
    SystemImage,
    /// Assesses a built OCI image's component inventory.
    OciImage,
}

/// Names one exact package/artifact or aggregate being assessed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InventorySubject {
    /// Stable portable reference within this inventory; never a database row ID.
    pub subject_ref: String,
    /// Publisher-scoped package coordinate.
    pub package_coordinate: String,
    /// Raw AOS package/release version.
    pub version: String,
    /// Exact target platform, including source evaluation's target.
    pub platform: String,
    /// Named package output or aggregate.
    pub output: String,
    /// Required artifact/source binding profile.
    pub kind: SubjectKind,
    /// Exact artifact identity, absent only for source-only subjects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<Sha256Digest>,
    /// Exact package-authored definition.
    pub scan_definition_digest: Sha256Digest,
    /// Exact published/built component inventory evidence.
    pub component_inventory_digest: Sha256Digest,
    /// Exact source content for a source-only subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_content_digest: Option<Sha256Digest>,
    /// Sorted exact member subjects for an aggregate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_refs: Vec<String>,
}

/// Binds upstream identity and patches/configuration to a containing subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ComponentInstance {
    /// Stable reference within this inventory.
    pub component_ref: String,
    /// Logical component identity within its definition.
    pub component_id: ComponentId,
    /// Exact containing subject, not a mutable channel name.
    pub subject_ref: String,
    /// Raw and comparison versions of the assessed component.
    pub current: ComponentVersion,
    /// Exact component definition admitted for this instance.
    pub scan_definition_digest: Sha256Digest,
    /// Supported advisory identities, schemes and declared coverage.
    pub security: SecurityDeclaration,
    /// Containing artifact identity; required for built subjects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<Sha256Digest>,
    /// Exact source binding when no built artifact exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_content_digest: Option<Sha256Digest>,
    /// Optional exact feature/configuration evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_digest: Option<Sha256Digest>,
    /// Optional exact applied patch set, including reviewed backports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch_set_digest: Option<Sha256Digest>,
}

impl ComponentInstance {
    /// Computes the component identity without an ambient artifact/name lookup.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid security identity, version text, references,
    /// or noncanonical/oversized content. Inventory admission checks containment.
    pub fn digest(&self) -> Result<Sha256Digest> {
        text(&self.component_ref, 128, "component reference")?;
        text(&self.subject_ref, 128, "containing subject reference")?;
        text(&self.current.upstream_id, 512, "upstream identity")?;
        text(&self.current.comparison_version, 256, "comparison version")?;
        self.security.validate()?;
        digest(COMPONENT_INSTANCE_V1, self)
    }
}

/// Classifies dependency exposure without confusing build tools with runtime use.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationshipKind {
    /// Is required to build the target but is not thereby shipped in it.
    BuildDependsOn,
    /// Contains the referenced upstream component.
    Contains,
    /// Requires the referenced subject/component at runtime.
    RuntimeDependsOn,
    /// Supplies source content for the referenced artifact.
    SourceOf,
}

/// Preserves one sorted typed edge of the admitted inventory graph.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InventoryRelationship {
    /// Source subject or component reference.
    pub from_ref: String,
    /// Explicit relationship semantics.
    pub kind: RelationshipKind,
    /// Target subject or component reference.
    pub to_ref: String,
}

/// Contains a finite normalized inventory and its declared/observed coverage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanInventoryV1 {
    /// Exact schema identity.
    pub schema: String,
    /// Subjects sorted by their portable reference.
    pub subjects: Vec<InventorySubject>,
    /// Instances sorted by their portable reference.
    pub components: Vec<ComponentInstance>,
    /// Edges sorted by source, kind and destination.
    pub relationships: Vec<InventoryRelationship>,
    /// Explicit inventory completeness; an empty component set is not a proof.
    pub coverage: DependencyCoverage,
}

impl ScanInventoryV1 {
    /// Decodes and validates a bounded portable inventory.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown/ambiguous fields, excessive scope,
    /// duplicate or dangling references, or invalid artifact/source bindings.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let inventory: Self = decode(bytes, "scan inventory")?;
        inventory.validate()?;
        Ok(inventory)
    }

    /// Validates closed identity, ordering, containment, and graph bounds.
    ///
    /// Cyclic dependency edges are allowed; consumers traverse with a visited
    /// set and an explicit work budget. Aggregate membership must be acyclic.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, invalid subject/component,
    /// incomplete bindings, duplicate/dangling references, or aggregate cycles.
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCAN_INVENTORY_V1 || self.subjects.is_empty() {
            bail!("invalid scan inventory schema or empty subject set");
        }
        if self.subjects.len() > 10_000
            || self.components.len() > 100_000
            || self.relationships.len() > 100_000
        {
            bail!("scan inventory exceeds graph limits");
        }
        text(&self.coverage.basis, 4096, "inventory coverage basis")?;
        if self
            .subjects
            .iter()
            .try_fold(0usize, |total, subject| {
                total
                    .checked_add(subject.member_refs.len())
                    .filter(|count| *count <= 100_000)
            })
            .is_none()
        {
            bail!("aggregate membership exceeds graph limits");
        }
        if self
            .subjects
            .windows(2)
            .any(|pair| pair[0].subject_ref >= pair[1].subject_ref)
            || self
                .components
                .windows(2)
                .any(|pair| pair[0].component_ref >= pair[1].component_ref)
        {
            bail!("inventory subjects/components must be sorted and unique");
        }
        sorted(&self.relationships, "inventory relationships")?;

        let subject_refs = self
            .subjects
            .iter()
            .map(|subject| subject.subject_ref.as_str())
            .collect::<BTreeSet<_>>();
        let mut references = subject_refs.clone();
        for subject in &self.subjects {
            for (field, value, maximum) in [
                ("subject reference", subject.subject_ref.as_str(), 128),
                (
                    "package coordinate",
                    subject.package_coordinate.as_str(),
                    1024,
                ),
                ("package version", subject.version.as_str(), 256),
                ("platform", subject.platform.as_str(), 128),
                ("output", subject.output.as_str(), 128),
            ] {
                text(value, maximum, field)?;
            }
            let source_only = subject.kind == SubjectKind::Source;
            if source_only != subject.source_content_digest.is_some()
                || source_only == subject.artifact_digest.is_some()
            {
                bail!("subject artifact/source binding disagrees with its kind");
            }
            sorted(&subject.member_refs, "aggregate member references")?;
            for member in &subject.member_refs {
                if member == &subject.subject_ref || !subject_refs.contains(member.as_str()) {
                    bail!("invalid aggregate member reference");
                }
            }
        }

        for component in &self.components {
            component.digest()?;
            if !references.insert(component.component_ref.as_str()) {
                bail!("subject/component reference collision");
            }
            let subject = self
                .subjects
                .binary_search_by(|subject| subject.subject_ref.cmp(&component.subject_ref))
                .ok()
                .and_then(|index| self.subjects.get(index))
                .ok_or_else(|| anyhow::anyhow!("component references a missing subject"))?;
            if component.artifact_digest != subject.artifact_digest
                || component.source_content_digest != subject.source_content_digest
            {
                bail!(
                    "component is bound to different artifact/source bytes than its containing subject"
                );
            }
        }
        for edge in &self.relationships {
            if !references.contains(edge.from_ref.as_str())
                || !references.contains(edge.to_ref.as_str())
            {
                bail!("inventory relationship references a missing node");
            }
        }
        self.validate_aggregate_membership()?;
        Ok(())
    }

    /// Computes the validated portable inventory identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid inventory or noncanonical/oversized data.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(SCAN_INVENTORY_V1, self)
    }

    fn validate_aggregate_membership(&self) -> Result<()> {
        // An iterative color traversal bounds stack use even for hostile chains.
        let mut finished = BTreeSet::new();
        let mut active = BTreeSet::new();
        for subject in &self.subjects {
            let mut stack = vec![(subject.subject_ref.as_str(), false)];
            while let Some((reference, exiting)) = stack.pop() {
                if exiting {
                    active.remove(reference);
                    finished.insert(reference);
                    continue;
                }
                if finished.contains(reference) {
                    continue;
                }
                if !active.insert(reference) {
                    bail!("aggregate membership contains a cycle");
                }
                stack.push((reference, true));
                let index = self
                    .subjects
                    .binary_search_by(|item| item.subject_ref.as_str().cmp(reference))
                    .map_err(|_| anyhow::anyhow!("aggregate references a missing subject"))?;
                for member in self.subjects[index].member_refs.iter().rev() {
                    stack.push((member.as_str(), false));
                }
            }
        }
        Ok(())
    }
}
