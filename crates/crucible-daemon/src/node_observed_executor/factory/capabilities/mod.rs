//! Selects one whole installed candidate before allocating native resources.
//!
//! Candidate recipes contain implementation choices, not provider claims. Each
//! candidate is independently regenerated from the measured local catalog.
//! Ambiguity refuses; the resolver never unions support across candidates.

pub(super) mod admission;
mod condition;
mod gem5;
mod native;
pub(super) mod policy;
mod staging;

pub use native::InstalledCapabilityClockFactory;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod native_tests;

#[cfg(test)]
mod host_exact_tests;

use super::{
    InstalledNodeCatalog, InstalledNodeSelection, InstalledPreparedWorld, NodeObservedError,
    PreparationSource, SelectedPreparation, refused,
};
use crate::node_scenario::NodeScenario;
use crucible::node_admission::{
    CAPABILITY_SELECTION_FORMAT, CapabilityBinding, CapabilityRequirements, CapabilitySelection,
};
use crucible_campaign::ExecutionId;
use crucible_node_contract::{Id, canonical};

/// Supplies one bounded complete-world recipe to the installed resolver.
#[derive(Clone, Debug)]
pub struct InstalledCapabilityCandidate {
    /// Names this complete alternative without imposing an implicit preference.
    pub id: Id,
    /// Selects every node and owner for this alternative.
    pub selections: Vec<InstalledNodeSelection>,
}

/// Retains one unambiguous installed resolution and its immutable authored demands.
///
/// Private fields prevent authored claims from constructing this resolution.
/// Preparation rechecks installation and the complete source-derived candidate.
#[derive(Clone)]
pub struct ResolvedCapabilityWorld {
    candidate: InstalledCapabilityCandidate,
    pub(super) requirements: CapabilityRequirements,
    scenario: NodeScenario,
    pub(super) requirements_bytes: Vec<u8>,
}

impl ResolvedCapabilityWorld {
    /// Borrows the exact complete scenario selected by mandatory capabilities.
    pub fn scenario(&self) -> &NodeScenario {
        &self.scenario
    }

    /// Borrows the exact source-selected candidate identity.
    pub fn candidate_id(&self) -> &Id {
        &self.candidate.id
    }
}

impl InstalledNodeCatalog {
    /// Resolves conjunctive requirements against bounded complete installed worlds.
    ///
    /// # Errors
    /// Refuses unknown/invalid demands, zero matches, ambiguous matches, invalid
    /// candidates, or unsupported installed operation/architecture/extension policy.
    /// No native resource or retirement slot is allocated during resolution.
    pub fn resolve_capabilities(
        &self,
        candidates: &[InstalledCapabilityCandidate],
        requirements: CapabilityRequirements,
    ) -> Result<ResolvedCapabilityWorld, NodeObservedError> {
        requirements
            .validate()
            .map_err(|error| refused(&error.to_string()))?;
        if candidates.is_empty()
            || candidates.len() > 64
            || candidates.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(refused(
                "capability candidates require a sorted finite unique roster",
            ));
        }
        let mut chosen = None;
        for candidate in candidates {
            let scenario = self.scenario(&candidate.selections)?;
            if policy::matches(&candidate.selections, &scenario, &requirements).is_err() {
                continue;
            }
            if chosen.is_some() {
                return Err(refused(
                    "capability requirements match multiple complete installed worlds",
                ));
            }
            chosen = Some((candidate, scenario));
        }
        let (candidate, scenario) = chosen.ok_or_else(|| {
            refused("no complete installed world satisfies mandatory capabilities")
        })?;
        let scenario = bind_requirements(scenario, &requirements)?;
        let requirements_bytes = canonical::canonical_json(&serde_json::to_value(&requirements)?)?;
        Ok(ResolvedCapabilityWorld {
            requirements_bytes,
            candidate: candidate.clone(),
            requirements,
            scenario,
        })
    }

    /// Resolves complete installed worlds while preserving the original authored demand body.
    ///
    /// # Errors
    /// Refuses invalid or excessive raw JSON, unavailable installed combinations,
    /// ambiguity or changed semantic predicates before native allocation.
    pub fn resolve_capabilities_raw(
        &self,
        candidates: &[InstalledCapabilityCandidate],
        original: &[u8],
    ) -> Result<ResolvedCapabilityWorld, NodeObservedError> {
        let demands: CapabilityRequirements =
            serde_json::from_value(canonical::parse_json(original, 1024 * 1024)?)?;
        let mut resolved = self.resolve_capabilities(candidates, demands)?;
        let baseline = self.scenario(&resolved.candidate.selections)?;
        resolved.scenario = bind_original_requirements(baseline, &resolved.requirements, original)?;
        resolved.requirements_bytes = original.to_vec();
        Ok(resolved)
    }

    /// Creates an ordinary observed executor from an authenticated capability resolution.
    ///
    /// # Errors
    /// Refuses changed selection, failed native enrollment, unsupported execution
    /// configuration, or unavailable durable activation and input storage.
    pub fn prepare_capability(
        &mut self,
        resolved: &ResolvedCapabilityWorld,
        configuration: crate::node_scenario::NodeRunConfiguration,
        execution: ExecutionId,
        blobs: std::sync::Arc<dyn crucible_cas::content_store::ImmutableBlobBackend>,
        refs: std::sync::Arc<dyn crucible_cas::content_store::MutableRefBackend>,
    ) -> Result<crate::node_observed_executor::NodeObservedBackend, NodeObservedError> {
        let prepared = self.prepare_capability_world(resolved, execution)?;
        Self::finish_observed(
            prepared,
            &resolved.candidate.selections,
            configuration,
            execution,
            blobs,
            refs,
        )
    }

    /// Prepares a revalidated capability-selected world under ordinary native custody.
    ///
    /// # Errors
    /// Refuses changed installed profiles, changed mandatory demands, unavailable
    /// custody or native enrollment. Ordinary all-owner activation remains required.
    pub fn prepare_capability_world(
        &mut self,
        resolved: &ResolvedCapabilityWorld,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedWorld, NodeObservedError> {
        self.prepare_capability_source(resolved, execution, None)
            .map(|value| value.0)
    }

    pub(super) fn prepare_capability_source(
        &mut self,
        resolved: &ResolvedCapabilityWorld,
        execution: ExecutionId,
        source: Option<&crucible::node_state::NativeArchiveRecord>,
    ) -> Result<
        (
            InstalledPreparedWorld,
            crucible::node_contract::ActivationRecord,
        ),
        NodeObservedError,
    > {
        let actual = self.scenario(&resolved.candidate.selections)?;
        policy::matches(
            &resolved.candidate.selections,
            &actual,
            &resolved.requirements,
        )?;
        if bind_original_requirements(actual, &resolved.requirements, &resolved.requirements_bytes)?
            .canonical_bytes()?
            != resolved.scenario.canonical_bytes()?
        {
            return Err(refused(
                "capability resolution changed before native preparation",
            ));
        }
        let original = source
            .map(crucible::node_state::NativeArchiveRecord::source_activation)
            .transpose()
            .map_err(|error| refused(&error.to_string()))?;
        let identity = resolved.scenario.world.identity()?;
        if source.is_some_and(|value| value.manifest().world_binding_hash != identity) {
            return Err(refused("original capability source world differs"));
        }
        if policy::gem5_ordinary(&resolved.candidate.selections) {
            if source.is_some() {
                return Err(refused(
                    "authored gem5 capability continuation is not qualified",
                ));
            }
            return super::native_state::public_catalog::prepare_capability(
                self,
                &resolved.candidate.selections,
                resolved,
                execution,
            );
        }
        let artifacts = self.artifacts.clone();
        self.prepare_world_with_selected_label(
            &resolved.candidate.selections,
            resolved.scenario.clone(),
            execution,
            &artifacts,
            None,
            SelectedPreparation {
                source: PreparationSource {
                    activation: original.as_ref(),
                    preserved_cut: source.map(|value| value.manifest().cut),
                },
                label: None,
                capabilities: Some(resolved),
            },
        )
    }
}

pub(super) fn bind_requirements(
    scenario: NodeScenario,
    requirements: &CapabilityRequirements,
) -> Result<NodeScenario, NodeObservedError> {
    requirements
        .validate()
        .map_err(|error| refused(&error.to_string()))?;
    let bytes = canonical::canonical_json(&serde_json::to_value(requirements)?)?;
    bind_original_requirements(scenario, requirements, &bytes)
}

pub(super) fn bind_original_requirements(
    mut scenario: NodeScenario,
    requirements: &CapabilityRequirements,
    original: &[u8],
) -> Result<NodeScenario, NodeObservedError> {
    if original.len() > 1024 * 1024 {
        return Err(refused(
            "original authored capability body exceeds finite credit",
        ));
    }
    let actual: CapabilityRequirements =
        serde_json::from_value(canonical::parse_json(original, 1024 * 1024)?)?;
    actual
        .validate()
        .map_err(|error| refused(&error.to_string()))?;
    if canonical::json_hash("crucible.capability-authored.v1", &actual)?
        != canonical::json_hash("crucible.capability-authored.v1", requirements)?
    {
        return Err(refused(
            "original authored capability body changed semantic predicates",
        ));
    }
    let bytes = original.to_vec();
    let requirements_ref = canonical::content_ref(
        &bytes,
        crucible::node_admission::CAPABILITY_REQUIREMENTS_MEDIA_TYPE,
    )?;
    let bindings = scenario
        .compatibility
        .iter()
        .map(|binding| {
            Ok(CapabilityBinding {
                node: binding.node_id.clone(),
                compatibility_hash: binding.identity()?,
            })
        })
        .collect::<Result<Vec<_>, NodeObservedError>>()?;
    let selection = CapabilitySelection {
        format: CAPABILITY_SELECTION_FORMAT.into(),
        schema_version: 1,
        base_scenario_ref: scenario.world.scenario_ref.clone(),
        requirements_ref: requirements_ref.clone(),
        bindings,
    };
    scenario
        .content
        .push(crate::node_scenario::ScenarioContent {
            reference: requirements_ref,
            bytes,
        });
    let bytes = canonical::canonical_json(&serde_json::to_value(selection)?)?;
    let reference = canonical::content_ref(
        &bytes,
        crucible::node_admission::CAPABILITY_SELECTION_MEDIA_TYPE,
    )?;
    scenario.world.scenario_ref = reference.clone();
    scenario
        .content
        .push(crate::node_scenario::ScenarioContent { reference, bytes });
    scenario
        .content
        .sort_by(|left, right| left.reference.hash.digest.cmp(&right.reference.hash.digest));
    scenario.canonical_bytes()?;
    Ok(scenario)
}

fn state_error(reason: impl std::fmt::Display) -> crucible::node_state::StateError {
    crucible::node_state::StateError::new(
        crucible::node_state::StateErrorCode::NativeEvidence,
        "installed capability Clock",
        reason.to_string(),
    )
}

impl InstalledNodeCatalog {
    /// Resolves cold preservation for one source-installed capability-bearing Clock.
    ///
    /// # Errors
    /// Refuses other topologies, changed artifacts, altered raw demands or any
    /// unsupported operation, extension, architecture or complete-world identity.
    pub fn installed_capability_clock_factory(
        &self,
        resolved: &ResolvedCapabilityWorld,
    ) -> Result<std::rc::Rc<InstalledCapabilityClockFactory>, NodeObservedError> {
        if !policy::standalone_clock(&resolved.candidate.selections) {
            return Err(refused(
                "no enrolled capability native factory for this complete world",
            ));
        }
        let baseline = self.scenario(&resolved.candidate.selections)?;
        policy::matches(
            &resolved.candidate.selections,
            &baseline,
            &resolved.requirements,
        )?;
        if bind_original_requirements(
            baseline.clone(),
            &resolved.requirements,
            &resolved.requirements_bytes,
        )?
        .canonical_bytes()?
            != resolved.scenario.canonical_bytes()?
        {
            return Err(refused(
                "installed capability source changed before native factory selection",
            ));
        }
        Ok(std::rc::Rc::new(InstalledCapabilityClockFactory {
            resolved: std::rc::Rc::new(resolved.clone()),
            installed: self.host_state_factory(&resolved.candidate.selections, &baseline)?,
        }))
    }

    /// Prepares the inactive fresh owner scope of the exact original Clock archive.
    ///
    /// # Errors
    /// Refuses unavailable installed preservation, another original complete
    /// world, changed requirements or native resource/custody exhaustion.
    pub fn prepare_capability_clock_restore(
        &mut self,
        resolved: &ResolvedCapabilityWorld,
        execution: ExecutionId,
        source: &crucible::node_state::NativeArchiveRecord,
    ) -> Result<
        (
            InstalledPreparedWorld,
            crucible::node_contract::ActivationRecord,
        ),
        NodeObservedError,
    > {
        self.installed_capability_clock_factory(resolved)?;
        self.prepare_capability_source(resolved, execution, Some(source))
    }
}
