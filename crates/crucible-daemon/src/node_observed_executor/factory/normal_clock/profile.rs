//! Regenerates the distinct preparation-bearing Clock source selection.
//!
//! The existing generic Clock profile is unchanged. This profile selects the
//! already implemented public Clock session and continuation codecs, preserving
//! every exact/capture guarantee and the whole source-owned world inventory.

use std::collections::BTreeMap;

use crate::node_scenario::{NodeScenario, ScenarioContent};
use crucible_node_contract::{Extensions, NodeBindingRef};

use super::*;

/// Selects the source-regenerated preparation-bearing portless Clock family.
///
/// This private-constructor selection is immutable data beneath the measured
/// catalog. Native preparation and normal class acceptance remain separate.
#[derive(Clone)]
pub struct InstalledNormalClockProfile {
    pub(in crate::node_observed_executor::factory) baseline: NodeScenario,
    pub(super) scenario: NodeScenario,
    pub(super) selection: InstalledNodeSelection,
}

impl InstalledNormalClockProfile {
    /// Borrows the complete source-owned Clock world and codec inventory.
    pub fn scenario(&self) -> &NodeScenario {
        &self.scenario
    }
}

impl InstalledNodeCatalog {
    /// Resolves the distinct public Clock profile from the actual installation.
    ///
    /// # Errors
    /// Refuses changed installation identity or unavailable exact source codecs.
    pub fn installed_normal_clock(&self) -> Result<InstalledNormalClockProfile, NodeObservedError> {
        if measure_executable(&self.host_executable)? != self.host_identity {
            return Err(refused("normal Clock installation changed"));
        }
        let selection = InstalledNodeSelection {
            node: Id::new("clock")?,
            owner: Id::new("owner/clock")?,
            kind: InstalledNodeKind::HostClock,
        };
        let baseline = self.scenario(std::slice::from_ref(&selection))?;
        let scenario = build(&baseline)?;
        Ok(InstalledNormalClockProfile {
            baseline,
            scenario,
            selection,
        })
    }

    /// Prepares the actual source-selected public Clock through ordinary custody.
    ///
    /// Every current behavioral policy still participates in source preflight
    /// and graph admission. This method grants neither a successful report nor
    /// activation; the same full readiness/publication barrier remains required.
    ///
    /// # Errors
    /// Refuses foreign or stale profiles, changed source selection, exhausted
    /// original custody or failed actual model/source/class qualification.
    pub fn prepare_normal_clock_world(
        &mut self,
        profile: &InstalledNormalClockProfile,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedWorld, NodeObservedError> {
        let current = self.installed_normal_clock()?;
        if current.scenario.canonical_bytes()? != profile.scenario.canonical_bytes()? {
            return Err(refused(
                "normal Clock profile differs from current installation",
            ));
        }
        let artifacts = self.artifacts.clone();
        self.prepare_world_with_selected_label(
            std::slice::from_ref(&profile.selection),
            profile.scenario.clone(),
            execution,
            &artifacts,
            None,
            super::super::SelectedPreparation {
                source: Default::default(),
                label: None,
                capabilities: None,
                normal_clock: Some(profile),
            },
        )
        .map(|(world, _)| world)
    }
    /// Generates fresh authority for this unchanged world from a signed source.
    ///
    /// The archive remains historical data until the real state factory admits
    /// its native/coordinator closure. The unused initial preparation follows
    /// the catalog's ordinary quarantine path; it is never used as a restore.
    ///
    /// # Errors
    /// Refuses changed installed selection, world/source/cut or reused lineage.
    pub fn prepare_normal_clock_restore_graph(
        &mut self,
        profile: &InstalledNormalClockProfile,
        source: &crucible::node_state::NativeArchiveRecord,
        execution: ExecutionId,
    ) -> Result<(AdmittedGraph, crucible::node_contract::ActivationRecord), NodeObservedError> {
        let current = self.installed_normal_clock()?;
        if current.scenario.canonical_bytes()? != profile.scenario.canonical_bytes()?
            || source.manifest().world_binding_hash != current.scenario.world.identity()?
            || source.manifest().scenario_ref != current.scenario.world.scenario_ref
        {
            return Err(refused(
                "normal Clock durable source differs from current complete profile",
            ));
        }
        let original = source.source_activation().map_err(super::super::native)?;
        let artifacts = self.artifacts.clone();
        let (prepared, target) = self.prepare_world_with_selected_label(
            std::slice::from_ref(&profile.selection),
            current.scenario,
            execution,
            &artifacts,
            None,
            super::super::SelectedPreparation {
                source: super::super::PreparationSource {
                    activation: Some(&original),
                    preserved_cut: Some(source.manifest().cut),
                },
                label: None,
                capabilities: None,
                normal_clock: Some(profile),
            },
        )?;
        drop(prepared.realization);
        Ok((prepared.graph, target))
    }
}

pub(in crate::node_observed_executor::factory) fn build(
    baseline: &NodeScenario,
) -> Result<NodeScenario, NodeObservedError> {
    if baseline.descriptors.len() != 1
        || baseline.compatibility.len() != 1
        || baseline.owners.len() != 1
        || baseline.descriptors[0].id.as_str() != "clock"
        || !baseline.descriptors[0].ports.is_empty()
        || baseline.compatibility[0]
            .implementation
            .implementation_id
            .as_str()
            != "crucible-host-clock"
        || !baseline.world.connections.is_empty()
        || !baseline.world.extensions.is_empty()
    {
        return Err(refused(
            "normal Clock requires its closed source-regenerated baseline",
        ));
    }
    let mut scenario = baseline.clone();
    let mut contents = scenario
        .content
        .into_iter()
        .map(|object| (object.reference.hash.digest.clone(), object))
        .collect::<BTreeMap<String, ScenarioContent>>();
    let binding = &mut scenario.compatibility[0];
    super::super::native_state::profile::select_public_preparation(
        &mut scenario.descriptors[0],
        binding,
        &mut contents,
        true,
        false,
    )?;
    let definition = super::super::profile::put_json(
        &mut contents,
        &serde_json::json!({
            "schema":"crucible.normal-source-clock/1",
            "source":"same measured host executable and complete actual portless integer Clock",
            "preparation":"actual original memory session, native ready and common owner map before publication",
            "timing":"identity picoseconds; strict exclusive ceiling; full superdense boundary settlement",
            "state":"unchanged native host envelope plus original public preparation-bearing continuation codec",
            "normal_qualification":"required independently retained original cases; no report supplied by configuration",
            "unsupported":["ports","alarms","autonomous worker","external input","fork","conditional replay"],
        }),
    )?;
    binding.qualification_refs.push(definition.clone());
    binding.qualification_refs.sort_by(|left, right| {
        (&left.hash.domain, &left.hash.digest).cmp(&(&right.hash.domain, &right.hash.digest))
    });
    let node_binding = NodeBindingRef {
        node_id: binding.node_id.clone(),
        binding_hash: binding.identity()?,
        extensions: Extensions::new(),
    };
    scenario.world.node_bindings = vec![node_binding.clone()];
    scenario.owners[0].node_bindings = vec![node_binding];
    scenario.world.scenario_ref = super::super::profile::put_json(
        &mut contents,
        &serde_json::json!({
            "schema":"crucible.normal-source-clock-world/1", "baseline":baseline.world.scenario_ref,
            "definition":definition, "nodes":scenario.descriptors, "compatibility":scenario.compatibility,
            "owners":scenario.owners,"connections":[],"external_inputs":[],
        }),
    )?;
    scenario.content = contents.into_values().collect();
    scenario.content.sort_by(|left, right| {
        (&left.reference.hash.domain, &left.reference.hash.digest)
            .cmp(&(&right.reference.hash.domain, &right.reference.hash.digest))
    });
    drop(scenario.canonical_bytes()?);
    Ok(scenario)
}
