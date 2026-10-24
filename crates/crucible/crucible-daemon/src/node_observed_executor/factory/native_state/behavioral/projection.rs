//! Preserves source identity while adding an independently accepted report.
//!
//! This projection is structural data. It grants no behavior, native custody or
//! current authority. The catalog authenticates the original accepted report
//! before issuing it and rechecks ordinary acceptance at full graph admission.

use super::super::super::{InstalledNodeCatalog, NodeObservedError, refused};
use super::super::host_group::profile::IndependentGroupProfile;
use crate::node_scenario::{NodeScenario, ScenarioContent};
use crucible_node_format::{BindingCompatibility, ContentRef, Id};
use std::{collections::BTreeMap, rc::Rc};

pub(in crate::node_observed_executor::factory) struct OriginalReportProjection {
    source: BTreeMap<Id, BindingCompatibility>,
    selected: BTreeMap<Id, BindingCompatibility>,
    original: ContentRef,
    bytes: Vec<u8>,
}

impl OriginalReportProjection {
    /// Constructs only the exact single-report addition accepted by the catalog.
    pub(in crate::node_observed_executor::factory) fn checked(
        source: &NodeScenario,
        selected: BTreeMap<Id, BindingCompatibility>,
        original: ContentRef,
        bytes: &[u8],
    ) -> Result<Self, NodeObservedError> {
        if source.compatibility.len() != 4 || selected.len() != 4 || bytes.len() > 4 * 1024 * 1024 {
            return Err(refused("behavioral projection original credit"));
        }
        original.verify(bytes)?;
        for binding in &source.compatibility {
            let actual = selected
                .get(&binding.node_id)
                .ok_or_else(|| refused("enrolled source node absent"))?;
            let mut expected = binding.clone();
            if expected.qualification_refs.contains(&original) {
                return Err(refused("source report was already enrolled"));
            }
            expected.qualification_refs.push(original.clone());
            expected.qualification_refs.sort();
            if actual != &expected {
                return Err(refused(
                    "behavioral enrollment changed original source semantics",
                ));
            }
        }
        // Count borrowed complete source geometry before retained body copies.
        super::unit::encode(&(source, &selected, &original, bytes)).map_err(error)?;
        Ok(Self {
            source: source
                .compatibility
                .iter()
                .map(|binding| (binding.node_id.clone(), binding.clone()))
                .collect(),
            selected,
            original,
            bytes: bytes.to_vec(),
        })
    }

    pub(in crate::node_observed_executor::factory::native_state) fn apply(
        &self,
        scenario: &mut NodeScenario,
    ) -> Result<(), NodeObservedError> {
        for binding in &mut scenario.compatibility {
            if self.source.get(&binding.node_id) != Some(binding) {
                return Err(refused(
                    "behavioral projection has foreign original binding",
                ));
            }
            *binding = self
                .selected
                .get(&binding.node_id)
                .ok_or_else(|| refused("behavioral projection node absent"))?
                .clone();
        }
        for reference in &mut scenario.world.node_bindings {
            reference.binding_hash = scenario
                .compatibility
                .iter()
                .find(|binding| binding.node_id == reference.node_id)
                .ok_or_else(|| refused("enrolled world participant absent"))?
                .identity()?;
        }
        for owner in &mut scenario.owners {
            for participant in &mut owner.node_bindings {
                participant.binding_hash = scenario
                    .compatibility
                    .iter()
                    .find(|binding| binding.node_id == participant.node_id)
                    .ok_or_else(|| refused("enrolled owner participant absent"))?
                    .identity()?;
            }
        }
        if scenario
            .content
            .iter()
            .any(|body| body.reference.hash == self.original.hash)
        {
            return Err(refused(
                "behavioral original body already has a source role",
            ));
        }
        scenario.content.try_reserve_exact(1).map_err(error)?;
        scenario.content.push(ScenarioContent {
            reference: self.original.clone(),
            bytes: self.bytes.clone(),
        });
        scenario.content.sort_by(|left, right| {
            (&left.reference.hash.domain, &left.reference.hash.digest)
                .cmp(&(&right.reference.hash.domain, &right.reference.hash.digest))
        });
        scenario.canonical_bytes()?;
        Ok(())
    }
}

pub(in crate::node_observed_executor::factory::native_state) fn enroll(
    mut profile: IndependentGroupProfile,
    catalog: &InstalledNodeCatalog,
) -> Result<IndependentGroupProfile, NodeObservedError> {
    let Some(projection) = catalog.original_gem5_behavioral_projection(&profile.scenario)? else {
        return Ok(profile);
    };
    // This Rc is still uniquely owned by the source constructor. Both CPU
    // views change together; original native qualification equality stays exact.
    let native = Rc::get_mut(&mut profile.native)
        .ok_or_else(|| refused("native source was shared before behavioral enrollment"))?;
    projection.apply(&mut native.scenario)?;
    native.behavioral_projection = Some(projection.clone());
    projection.apply(&mut profile.scenario)?;
    Ok(profile)
}

fn error(error: impl std::fmt::Display) -> NodeObservedError {
    refused(&error.to_string())
}
