//! Binds authored demands to the installed closed preserving condition world.
//!
//! Resolution retains exact source policy bytes. Native capture and restoration
//! still use the genuine Host archive, original Stop journal and owning driver.

use super::*;
use crucible::node_state::HostArchiveRecord;
use crucible_node_contract::ContentRef;
use std::rc::Rc;

impl InstalledNodeCatalog {
    /// Resolves a complete preserving Source/Block/observer capability recipe.
    ///
    /// # Errors
    /// Refuses unsupported topologies, raw demands, operations, policy bodies or
    /// independently installed artifacts before allocating native resources.
    pub fn resolve_condition_capabilities(
        &self,
        selections: &[InstalledNodeSelection],
        original: &[u8],
    ) -> Result<ResolvedCapabilityWorld, NodeObservedError> {
        if !policy::condition_preservation(selections) {
            return Err(refused(
                "capability condition requires the qualified closed Block roster",
            ));
        }
        self.resolve_capabilities_raw(
            &[InstalledCapabilityCandidate {
                id: Id::new("condition-preserving")?,
                selections: selections.to_vec(),
            }],
            original,
        )
    }

    /// Regenerates the same capability recipe from authenticated original inputs.
    ///
    /// The archive supplies original bytes only for independently enrolled
    /// artifacts. It neither installs a new source nor creates native authority.
    ///
    /// # Errors
    /// Refuses changed installation, missing original bodies, unsupported
    /// requirements or another complete signed world.
    pub fn resolve_condition_capabilities_from_archive(
        &self,
        selections: &[InstalledNodeSelection],
        original: &[u8],
        record: &HostArchiveRecord,
    ) -> Result<ResolvedCapabilityWorld, NodeObservedError> {
        if !policy::condition_preservation(selections) {
            return Err(refused(
                "capability condition archive has an unsupported roster",
            ));
        }
        let artifacts =
            super::super::archive_artifacts::materialize(&self.artifacts, selections, record)?;
        let baseline = super::super::profile::build_world(
            selections,
            &self.host_identity,
            &self.device_identity,
            artifacts.registry(),
        )?
        .scenario;
        let requirements: CapabilityRequirements =
            serde_json::from_value(canonical::parse_json(original, 1024 * 1024)?)?;
        policy::matches(selections, &baseline, &requirements)?;
        let scenario = bind_original_requirements(baseline, &requirements, original)?;
        if record.manifest().world_binding_hash != scenario.world.identity()?
            || record.manifest().scenario_ref != scenario.world.scenario_ref
        {
            return Err(refused(
                "original capability condition archive names another whole world",
            ));
        }
        Ok(ResolvedCapabilityWorld {
            candidate: InstalledCapabilityCandidate {
                id: Id::new("condition-preserving")?,
                selections: selections.to_vec(),
            },
            requirements,
            scenario,
            requirements_bytes: original.to_vec(),
        })
    }

    /// Authenticates installed condition preservation beneath a capability root.
    ///
    /// # Errors
    /// Refuses another topology, changed raw demand wrapper or source policy.
    pub fn installed_capability_condition_factory(
        &self,
        resolved: &ResolvedCapabilityWorld,
    ) -> Result<Rc<super::super::InstalledHostStateFactory>, NodeObservedError> {
        let baseline = self.scenario(&resolved.candidate.selections)?;
        let factory = self.host_state_factory(&resolved.candidate.selections, &baseline)?;
        bind_factory(factory, resolved)
    }

    /// Authenticates a fresh installed condition factory from its signed source.
    ///
    /// # Errors
    /// Refuses missing original enrolled artifacts, changed demands or contracts.
    pub fn installed_capability_condition_factory_from_archive(
        &self,
        resolved: &ResolvedCapabilityWorld,
        record: &HostArchiveRecord,
    ) -> Result<Rc<super::super::InstalledHostStateFactory>, NodeObservedError> {
        let artifacts = super::super::archive_artifacts::materialize(
            &self.artifacts,
            &resolved.candidate.selections,
            record,
        )?;
        let baseline = super::super::profile::build_world(
            &resolved.candidate.selections,
            &self.host_identity,
            &self.device_identity,
            artifacts.registry(),
        )?
        .scenario;
        let factory = self.host_state_factory_with_artifacts(
            &resolved.candidate.selections,
            &baseline,
            artifacts.registry(),
        )?;
        bind_factory(factory, resolved)
    }

    /// Prepares fresh inactive host authority for the original capability world.
    ///
    /// # Errors
    /// Refuses unsupported condition scope, changed signed world, source closure,
    /// raw demands, installed contracts or exhausted native custody.
    pub fn prepare_capability_condition_restore(
        &mut self,
        resolved: &ResolvedCapabilityWorld,
        execution: ExecutionId,
        record: &HostArchiveRecord,
    ) -> Result<
        (
            crucible::node_admission::AdmittedGraph,
            crucible::node_contract::ActivationRecord,
        ),
        NodeObservedError,
    > {
        self.installed_capability_condition_factory_from_archive(resolved, record)?;
        if record.manifest().world_binding_hash != resolved.scenario.world.identity()?
            || record.manifest().scenario_ref != resolved.scenario.world.scenario_ref
        {
            return Err(refused(
                "signed condition source differs from exact capability selection",
            ));
        }
        let source = record
            .source_activation(4 * 1024 * 1024)
            .map_err(super::super::native)?;
        let artifacts = super::super::archive_artifacts::materialize(
            &self.artifacts,
            &resolved.candidate.selections,
            record,
        )?;
        let (prepared, target) = self.prepare_world_with_selected_label(
            &resolved.candidate.selections,
            resolved.scenario.clone(),
            execution,
            artifacts.registry(),
            None,
            SelectedPreparation {
                source: PreparationSource {
                    activation: Some(&source),
                    preserved_cut: Some(record.manifest().cut),
                },
                label: None,
                capabilities: Some(resolved),
            },
        )?;
        drop(prepared.realization);
        Ok((prepared.graph, target))
    }
}

fn bind_factory(
    factory: Rc<super::super::InstalledHostStateFactory>,
    resolved: &ResolvedCapabilityWorld,
) -> Result<Rc<super::super::InstalledHostStateFactory>, NodeObservedError> {
    let factory = Rc::try_unwrap(factory)
        .map_err(|_| refused("new installed factory unexpectedly shared before binding"))?;
    Ok(Rc::new(factory.with_condition_capabilities(resolved)?))
}

impl ResolvedCapabilityWorld {
    pub(in crate::node_observed_executor::factory) fn condition_baseline(
        &self,
        baseline: &NodeScenario,
    ) -> Result<(), NodeObservedError> {
        if !policy::condition_preservation(&self.candidate.selections) {
            return Err(refused(
                "capability factory is outside qualified condition scope",
            ));
        }
        policy::matches(&self.candidate.selections, baseline, &self.requirements)?;
        if bind_original_requirements(
            baseline.clone(),
            &self.requirements,
            &self.requirements_bytes,
        )?
        .canonical_bytes()?
            != self.scenario.canonical_bytes()?
        {
            return Err(refused("original capability condition selection changed"));
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::factory) fn condition_dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Option<Vec<ContentRef>>, crucible::node_state::StateError> {
        let selection: CapabilitySelection = serde_json::from_slice(
            &self
                .scenario
                .content
                .iter()
                .find(|object| object.reference == self.scenario.world.scenario_ref)
                .ok_or_else(|| state_error("capability selection body absent"))?
                .bytes,
        )
        .map_err(state_error)?;
        if reference != &self.scenario.world.scenario_ref
            && reference != &selection.requirements_ref
        {
            return Ok(None);
        }
        let original = self
            .scenario
            .content
            .iter()
            .find(|object| &object.reference == reference)
            .ok_or_else(|| state_error("capability policy body absent"))?;
        if original.bytes != bytes {
            return Err(state_error("capability original policy body differs"));
        }
        let count = if reference == &self.scenario.world.scenario_ref {
            2
        } else {
            self.requirements
                .nodes
                .iter()
                .try_fold(0usize, |total, node| {
                    node.operations
                        .len()
                        .checked_mul(2)
                        .and_then(|n| n.checked_add(1))
                        .and_then(|n| n.checked_add(total))
                })
                .ok_or_else(|| state_error("capability dependency credit overflow"))?
        };
        if count > maximum {
            return Err(state_error("capability dependency credit unavailable"));
        }
        let mut dependencies = Vec::new();
        dependencies.try_reserve_exact(count).map_err(state_error)?;
        if reference == &self.scenario.world.scenario_ref {
            dependencies.extend([selection.base_scenario_ref, selection.requirements_ref]);
        } else {
            for node in &self.requirements.nodes {
                dependencies.push(node.timing.policy_ref.clone());
                for operation in &node.operations {
                    dependencies.extend([
                        operation.facet.configuration_ref.clone(),
                        operation.facet.guarantees_ref.clone(),
                    ]);
                }
            }
        }
        dependencies.sort();
        dependencies.dedup();
        Ok(Some(dependencies))
    }
}

fn state_error(reason: impl std::fmt::Display) -> crucible::node_state::StateError {
    crucible::node_state::StateError::new(
        crucible::node_state::StateErrorCode::NativeEvidence,
        "installed capability condition",
        reason.to_string(),
    )
}
