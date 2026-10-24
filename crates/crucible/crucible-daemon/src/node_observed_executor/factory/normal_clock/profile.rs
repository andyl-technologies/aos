//! Regenerates the distinct preparation-bearing Clock source selection.
//!
//! The existing generic Clock profile is unchanged. This profile selects the
//! already implemented public Clock session and continuation codecs, preserving
//! every exact/capture guarantee and the whole source-owned world inventory.

use std::collections::BTreeMap;

use crate::node_scenario::{NodeScenario, ScenarioContent};
use crucible_node_format::{Extensions, NodeBindingRef};

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
        let baseline = super::super::profile::build_world(
            std::slice::from_ref(&selection),
            &self.host_identity,
            &self.device_identity,
            &self.artifacts,
        )?
        .scenario;
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
        source: &crucible_engine::node_state::NativeArchiveRecord,
        execution: ExecutionId,
    ) -> Result<
        (
            AdmittedGraph,
            crucible_engine::node_contract::ActivationRecord,
        ),
        NodeObservedError,
    > {
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
    build_selected(baseline, &[("clock", "owner/clock")])
}

// Only these two closed source-built populations select this implementation.
// There is no caller-supplied native node, qualification label or ready record.
fn build_selected(
    baseline: &NodeScenario,
    expected: &[(&str, &str)],
) -> Result<NodeScenario, NodeObservedError> {
    if baseline.descriptors.len() != expected.len()
        || baseline.compatibility.len() != expected.len()
        || baseline.owners.len() != expected.len()
        || baseline
            .descriptors
            .iter()
            .zip(expected)
            .any(|(node, (id, _))| node.id.as_str() != *id || !node.ports.is_empty())
        || baseline
            .compatibility
            .iter()
            .zip(expected)
            .any(|(binding, (node, owner))| {
                binding.node_id.as_str() != *node
                    || binding.execution_owner.id.as_str() != *owner
                    || binding.implementation.implementation_id.as_str() != "crucible-host-clock"
            })
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
    for (descriptor, binding) in scenario
        .descriptors
        .iter_mut()
        .zip(&mut scenario.compatibility)
    {
        // This closed source family already authenticated the actual Clock
        // implementation above. Participant IDs do not select a backend codec.
        super::super::native_state::profile::select_public_preparation_selected(
            descriptor,
            binding,
            &mut contents,
            true,
            false,
            true,
        )?;
    }
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
    for binding in &mut scenario.compatibility {
        binding.qualification_refs.push(definition.clone());
        binding.qualification_refs.sort_by(|left, right| {
            (&left.hash.domain, &left.hash.digest).cmp(&(&right.hash.domain, &right.hash.digest))
        });
    }
    scenario.world.node_bindings = scenario
        .compatibility
        .iter()
        .map(|binding| {
            Ok(NodeBindingRef {
                node_id: binding.node_id.clone(),
                binding_hash: binding.identity()?,
                extensions: Extensions::new(),
            })
        })
        .collect::<Result<Vec<_>, NodeObservedError>>()?;
    for owner in &mut scenario.owners {
        for participant in &mut owner.node_bindings {
            participant.binding_hash = scenario
                .compatibility
                .iter()
                .find(|binding| binding.node_id == participant.node_id)
                .ok_or_else(|| refused("Clock owner participant absent"))?
                .identity()?;
        }
    }
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

pub(super) const ACTIVATION_CLOCKS: [(&str, &str); 2] =
    [("clock-a", "owner/clock-a"), ("clock-b", "owner/clock-b")];

impl InstalledNodeCatalog {
    pub(super) fn prepare_original_clock_activation_world(
        &mut self,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedWorld, NodeObservedError> {
        if measure_executable(&self.host_executable)? != self.host_identity {
            return Err(refused("Clock activation fixture source changed"));
        }
        let selections = ACTIVATION_CLOCKS
            .iter()
            .map(|(node, owner)| {
                Ok(InstalledNodeSelection {
                    node: Id::new(*node)?,
                    owner: Id::new(*owner)?,
                    kind: InstalledNodeKind::HostClock,
                })
            })
            .collect::<Result<Vec<_>, NodeObservedError>>()?;
        let baseline = super::super::profile::build_world(
            &selections,
            &self.host_identity,
            &self.device_identity,
            &self.artifacts,
        )?
        .scenario;
        let scenario = build_selected(&baseline, &ACTIVATION_CLOCKS)?;
        let profile = InstalledNormalClockProfile {
            baseline,
            scenario: scenario.clone(),
            selection: selections[0].clone(),
        };
        let artifacts = self.artifacts.clone();
        self.prepare_world_with_selected_label(
            &selections,
            scenario,
            execution,
            &artifacts,
            None,
            super::super::SelectedPreparation {
                source: Default::default(),
                label: None,
                capabilities: None,
                normal_clock: Some(&profile),
            },
        )
        .map(|(world, _)| world)
    }
}

pub(in crate::node_observed_executor::factory) fn regenerate_selected(
    baseline: &NodeScenario,
) -> Result<NodeScenario, NodeObservedError> {
    if baseline.descriptors.len() == 1 {
        build(baseline)
    } else {
        build_selected(baseline, &ACTIVATION_CLOCKS)
    }
}

#[cfg(test)]
mod activation_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn baseline() -> Result<NodeScenario, NodeObservedError> {
        let host = canonical::content_ref(
            b"source-data-only-clock-profile",
            "application/octet-stream",
        )?;
        let selections = ACTIVATION_CLOCKS
            .iter()
            .map(|(node, owner)| {
                Ok(InstalledNodeSelection {
                    node: Id::new(*node)?,
                    owner: Id::new(*owner)?,
                    kind: InstalledNodeKind::HostClock,
                })
            })
            .collect::<Result<Vec<_>, NodeObservedError>>()?;
        Ok(
            super::super::super::profile::build_world(&selections, &host, &host, &BTreeMap::new())?
                .scenario,
        )
    }

    #[test]
    fn two_original_clocks_keep_independent_owners_and_complete_public_preparation_bindings()
    -> TestResult {
        let original = baseline()?;
        let before = original.canonical_bytes()?;
        let selected = build_selected(&original, &ACTIVATION_CLOCKS)?;
        assert_eq!(original.canonical_bytes()?, before);
        assert_eq!(
            selected.canonical_bytes()?,
            regenerate_selected(&original)?.canonical_bytes()?
        );
        assert_eq!(selected.descriptors.len(), 2);
        assert_eq!(selected.owners.len(), 2);
        assert_ne!(selected.owners[0].owner.id, selected.owners[1].owner.id);
        assert!(
            selected.owners[0]
                .owner
                .state_domain_ids
                .iter()
                .all(|id| !selected.owners[1].owner.state_domain_ids.contains(id))
        );
        for (index, (old, new)) in original
            .compatibility
            .iter()
            .zip(&selected.compatibility)
            .enumerate()
        {
            assert_eq!(old.execution_owner, new.execution_owner);
            assert_eq!(old.capture_owner, new.capture_owner);
            assert_eq!(old.guarantees_ref, new.guarantees_ref);
            assert_eq!(old.implementation.artifacts, new.implementation.artifacts);
            assert!(
                new.implementation.formats.contains(
                    &crucible_engine::node_adapters::host_public_clock_preparation_schema()
                        .map_err(|error| error.reason)?
                )
            );
            assert!(
                new.implementation.formats.contains(
                    &crucible_engine::node_adapters::host_public_clock_continuation_schema()
                        .map_err(|error| error.reason)?
                )
            );
            assert!(
                !new.implementation.formats.contains(
                    &crucible_engine::node_adapters::gem5::gem5_public_preparation_schema()
                        .map_err(|error| error.reason)?
                )
            );
            assert!(
                !new.implementation.formats.contains(
                    &crucible_engine::node_adapters::gem5::gem5_public_continuation_schema()
                        .map_err(|error| error.reason)?
                )
            );
            let configuration = selected
                .content
                .iter()
                .find(|object| object.reference == selected.descriptors[index].configuration_ref)
                .ok_or("selected original Clock configuration absent")?;
            let configuration: serde_json::Value = serde_json::from_slice(&configuration.bytes)?;
            assert_eq!(
                configuration["public_preparation_schema"],
                serde_json::to_value(
                    crucible_engine::node_adapters::host_public_clock_preparation_schema()
                        .map_err(|error| error.reason)?
                )?
            );
            assert_eq!(
                configuration["public_continuation_schema"],
                serde_json::to_value(
                    crucible_engine::node_adapters::host_public_clock_continuation_schema()
                        .map_err(|error| error.reason)?
                )?
            );
            assert_eq!(
                selected.world.node_bindings[index].binding_hash,
                new.identity()?
            );
            assert_eq!(
                selected.owners[index].node_bindings[0].binding_hash,
                new.identity()?
            );
        }
        Ok(())
    }

    #[test]
    fn two_clock_source_refuses_aliased_owner_or_a_substituted_participant() -> TestResult {
        let mut original = baseline()?;
        original.compatibility[1].execution_owner =
            original.compatibility[0].execution_owner.clone();
        assert!(build_selected(&original, &ACTIVATION_CLOCKS).is_err());
        let mut original = baseline()?;
        original.descriptors[1].id = Id::new("clock-c")?;
        assert!(build_selected(&original, &ACTIVATION_CLOCKS).is_err());
        let original = baseline()?;
        assert!(build(&original).is_err());
        Ok(())
    }
}

impl crate::node_qualification::RetainedMetadataOwned for InstalledNormalClockProfile {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            baseline,
            scenario,
            selection,
        } = self;
        counter.charge(baseline)?;
        counter.charge(scenario)?;
        counter.charge(selection)
    }
}
