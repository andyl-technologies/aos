//! Owns the selected flat, source-authored immutable reconstruction roster.
//!
//! The closed metadata codec keeps every regenerated definition and installed
//! artifact as an explicitly named opaque leaf. Its root declares the complete
//! positive roster; nested JSON values never select edges or native authority.
//! Original enrollment, native model, request, receipt and ACK proof bodies are
//! outside this registry and retain their separate authenticated native readers.
//!
//! ```json
//! {"schema":"crucible.independent-group.metadata.v1","members":[]}
//! ```

use std::{collections::BTreeMap, io};

use crucible::node_state::{StateError, VerifiedStateContent};
use crucible_node_contract::{ContentRef, Validate, canonical};
use serde::Serialize;

use super::super::super::{InstalledNodeCatalog, NodeObservedError, refused};
use super::super::profile::MixedProfile;
use super::source::error;
use crate::node_scenario::{MAX_NODE_SCENARIO_BYTES, NodeScenario, ScenarioContent};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MetadataRole {
    /// Retains exact opaque bytes emitted by the selected source definition.
    SourceDefinition,
    /// Retains exact artifact bytes independently measured by the source installer.
    InstalledArtifact,
}

#[derive(Serialize)]
struct Member {
    reference: ContentRef,
    role: MetadataRole,
}

#[derive(Serialize)]
struct Record {
    schema: &'static str,
    members: Vec<Member>,
}

/// Retains one exact source root and its complete positive metadata members.
pub(super) struct MetadataClosure {
    root: ContentRef,
    body: Vec<u8>,
    members: Vec<Member>,
    capability: Option<super::capability_metadata::CapabilityMetadata>,
}

impl MetadataClosure {
    /// Attaches the complete metadata codec to the selected source graph.
    ///
    /// # Errors
    /// Refuses invalid references, exhausted credits, missing installed artifacts
    /// or a world/owner participant absent from the original source roster.
    pub(super) fn install(
        scenario: &mut NodeScenario,
        native: &MixedProfile,
        catalog: &InstalledNodeCatalog,
    ) -> Result<Self, NodeObservedError> {
        let mut members = BTreeMap::new();
        // Charge the borrowed member serialization before retaining references.
        // The fixed root/schema/array punctuation fits the reserved 256 bytes.
        let mut credit = Credit(MAX_NODE_SCENARIO_BYTES.saturating_sub(256));
        for object in &scenario.content {
            add_member(
                &mut members,
                &object.reference,
                MetadataRole::SourceDefinition,
                &mut credit,
            )?;
        }
        for reference in [&catalog.host_identity, &catalog.device_identity] {
            add_member(
                &mut members,
                reference,
                MetadataRole::InstalledArtifact,
                &mut credit,
            )?;
        }
        for name in [
            "native_executable",
            "controller",
            "model",
            "dmtcp_launch",
            "dmtcp_restart",
            "mtcp_restart",
            "image_guard",
            "auditor",
        ] {
            let artifact = native.installed.artifact(name)?;
            add_member(
                &mut members,
                &artifact.content,
                MetadataRole::InstalledArtifact,
                &mut credit,
            )?;
        }
        let guest = native.installed.guest(&native.isa)?;
        add_member(
            &mut members,
            &guest.content,
            MetadataRole::InstalledArtifact,
            &mut credit,
        )?;
        let record = Record {
            schema: "crucible.independent-group.metadata.v1",
            members: members
                .into_iter()
                .map(|(reference, role)| Member { reference, role })
                .collect(),
        };
        let body = canonical::canonical_json(&serde_json::to_value(&record)?)?;
        if body.len() > MAX_NODE_SCENARIO_BYTES {
            return Err(refused("original metadata roster exceeds root credit"));
        }
        let root = canonical::content_ref(&body, "application/json")?;
        scenario.content.push(ScenarioContent {
            reference: root.clone(),
            bytes: body.clone(),
        });
        scenario.content.sort_by(|left, right| {
            (&left.reference.hash.domain, &left.reference.hash.digest)
                .cmp(&(&right.reference.hash.domain, &right.reference.hash.digest))
        });

        for binding in &mut scenario.compatibility {
            if binding.node_id.as_str() == "cpu" || binding.node_id.as_str() == "clock" {
                continue;
            }
            binding.qualification_refs.push(root.clone());
            binding.qualification_refs.sort();
            binding.qualification_refs.dedup();
        }
        for owner in &mut scenario.owners {
            for participant in &mut owner.node_bindings {
                let binding = scenario
                    .compatibility
                    .iter()
                    .find(|binding| binding.node_id == participant.node_id)
                    .ok_or_else(|| refused("metadata roster has a foreign owner participant"))?;
                participant.binding_hash = binding.identity()?;
            }
        }
        for binding in &mut scenario.world.node_bindings {
            binding.binding_hash = scenario
                .compatibility
                .iter()
                .find(|selected| selected.node_id == binding.node_id)
                .ok_or_else(|| refused("metadata roster has a foreign world participant"))?
                .identity()?;
        }
        scenario.canonical_bytes()?;
        Ok(Self {
            root,
            body,
            members: record.members,
            capability: None,
        })
    }

    /// Adds the distinct typed outer codec while retaining the original root.
    pub(super) fn attach_capabilities(
        &mut self,
        baseline: &NodeScenario,
        selected: &NodeScenario,
    ) -> Result<(), NodeObservedError> {
        if self.capability.is_some() {
            return Err(refused("original capability metadata was already selected"));
        }
        self.capability = Some(super::capability_metadata::CapabilityMetadata::new(
            baseline,
            selected,
            &self.root,
            self.members.iter().map(|member| &member.reference),
        )?);
        Ok(())
    }

    pub(super) fn credit(
        &self,
    ) -> Result<&super::archive_credit::ArchiveCredit, NodeObservedError> {
        self.capability
            .as_ref()
            .map(|codec| codec.credit())
            .ok_or_else(|| refused("complete archive credit requires selected capability scope"))
    }

    pub(super) fn credit_body(&self, reference: &ContentRef) -> Option<&[u8]> {
        self.capability
            .as_ref()
            .map(|codec| codec.credit())
            .filter(|credit| credit.reference() == reference)
            .map(|credit| credit.body())
    }

    /// Returns a role only for an exact full reference in the authored roster.
    pub(super) fn role(&self, reference: &ContentRef) -> Option<MetadataRole> {
        if self
            .capability
            .as_ref()
            .is_some_and(|codec| codec.contains(reference))
        {
            return Some(MetadataRole::SourceDefinition);
        }
        self.members
            .iter()
            .find(|member| &member.reference == reference)
            .map(|member| member.role)
    }

    /// Identifies the exact root that owns the complete reconstruction roster.
    pub(super) fn is_root(&self, reference: &ContentRef) -> bool {
        &self.root == reference
    }

    /// Enumerates positive edges only from the authenticated complete root.
    ///
    /// # Errors
    /// Refuses changed original bytes, foreign full references, missing roles
    /// or insufficient credit before copying any member reference.
    pub(super) fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        reference.verify(bytes).map_err(error)?;
        if let Some(codec) = &self.capability
            && let Some(dependencies) = codec.dependencies(reference, bytes, maximum)?
        {
            return Ok(dependencies);
        }
        if !self.is_root(reference) {
            return self.role(reference).map(|_| Vec::new()).ok_or_else(|| {
                error("immutable object has no exact source-authored metadata role")
            });
        }
        if bytes != self.body || self.members.len() > maximum {
            return Err(error(
                "original metadata root body or complete roster credit differs",
            ));
        }
        let mut references = Vec::new();
        references
            .try_reserve_exact(self.members.len())
            .map_err(error)?;
        references.extend(self.members.iter().map(|member| member.reference.clone()));
        Ok(references)
    }

    /// Reopens the exact original root and every declared reconstruction member.
    ///
    /// # Errors
    /// Refuses missing, corrupted or foreign-role signed original content.
    pub(super) fn authenticate_complete(
        &self,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        if content.get(&self.root) != Some(self.body.as_slice()) {
            return Err(error("signed original metadata root is absent or differs"));
        }
        for member in &self.members {
            let bytes = content.get(&member.reference).ok_or_else(|| {
                error("signed original metadata member is absent or has a foreign role")
            })?;
            member.reference.verify(bytes).map_err(error)?;
        }
        if let Some(codec) = &self.capability {
            codec.authenticate_complete(content)?;
        }
        Ok(())
    }
}

fn add_member(
    members: &mut BTreeMap<ContentRef, MetadataRole>,
    reference: &ContentRef,
    role: MetadataRole,
    credit: &mut Credit,
) -> Result<(), NodeObservedError> {
    reference.validate()?;
    if members.contains_key(reference) {
        return Ok(());
    }
    if members.len() >= 16_384 {
        return Err(refused(
            "original metadata roster exceeds finite object credit",
        ));
    }
    #[derive(Serialize)]
    struct BorrowedMember<'a> {
        reference: &'a ContentRef,
        role: MetadataRole,
    }
    serde_json::to_writer(&mut *credit, &BorrowedMember { reference, role })?;
    io::Write::write_all(credit, b",")
        .map_err(|_| refused("original metadata root credit exceeded"))?;
    members.insert(reference.clone(), role);
    Ok(())
}

struct Credit(usize);

impl io::Write for Credit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("original metadata root credit exceeded"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
