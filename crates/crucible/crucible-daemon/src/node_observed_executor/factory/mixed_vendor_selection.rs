//! Resolves complete installed provider partitions through ordinary node selection.
//!
//! A definition names data already installed by the operator. It cannot combine
//! independently accepted singleton worlds into a qualified mixed world. The
//! existing registry reauthenticates the complete world source, every local
//! provider and ordinary behavioral acceptance before original native birth.

use std::{io::Write, rc::Rc};

use crucible_campaign::ExecutionId;
use crucible_engine::node_contract::{
    ActivationRecord, ProviderPlanningRequest, ProviderPreparationPlan, ProviderRegistryLimits,
    ProviderWorldSelection, RuntimeLimits,
};
use crucible_node_format::{ContentRef, Id, ResourceLimits, Validate};
use serde::Serialize;

use super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, InstalledPreparedWorld,
    NodeObservedError, native, refused,
};
use crate::node_scenario::NodeScenario;

#[cfg(test)]
mod tests;

const MAXIMUM_DEFINITIONS: usize = 64;
const MAXIMUM_DEFINITION_BYTES: usize = 16 * 1024 * 1024;

/// Names one original installed provider's complete local contribution.
///
/// This operator configuration has no deserializer and grants no native
/// authority. Local plans must partition the complete selected world exactly.
#[derive(Serialize)]
pub struct InstalledVendorContribution {
    /// Names an existing provider in the catalog's original registry.
    pub provider: Id,
    /// Selects its exact source-installed profile.
    pub profile: Id,
    /// Binds the complete immutable provider configuration.
    pub configuration: ContentRef,
    /// Lists all contributed node identities in strictly increasing order.
    pub nodes: Vec<Id>,
    /// Retains the independently selected local resource ceilings.
    pub resources: ResourceLimits,
    /// Retains the exact source-regenerated local descriptor and binding plan.
    pub plan: ProviderPreparationPlan,
}

impl InstalledVendorContribution {
    fn borrowed(&self) -> ProviderWorldSelection<'_> {
        ProviderWorldSelection {
            provider: &self.provider,
            selection: ProviderPlanningRequest {
                profile: &self.profile,
                configuration: &self.configuration,
                nodes: &self.nodes,
                resources: &self.resources,
                limits: ProviderRegistryLimits::default(),
            },
            plan: &self.plan,
        }
    }
}

/// Supplies one complete mixed-world definition independently of portable input.
///
/// Installation creates no native participant or activation permit. The
/// registry's separately installed complete-world source and ordinary class
/// policy remain mandatory at preparation, including their original revision
/// leases. The definition is bound to one observed execution and activation.
pub struct InstalledMixedVendorWorldRequest {
    /// Lists complete portable selections in strictly increasing node order.
    pub selections: Vec<InstalledNodeSelection>,
    /// Lists the complete disjoint partition in provider/profile order.
    pub contributions: Vec<InstalledVendorContribution>,
    /// Retains the independently authored complete scenario, including connections.
    pub scenario: NodeScenario,
    /// Binds the original observed execution without granting its nonce permit.
    pub execution: ExecutionId,
    /// Binds the complete original world and owner incarnation roster.
    pub activation: ActivationRecord,
    /// Narrows the one global runtime's finite accounting ceilings.
    pub runtime_limits: RuntimeLimits,
}

pub(super) struct InstalledMixedVendorWorld {
    contributions: Vec<InstalledVendorContribution>,
    scenario: NodeScenario,
    execution: ExecutionId,
    activation: ActivationRecord,
    runtime_limits: RuntimeLimits,
    retained_bytes: usize,
}

impl InstalledNodeCatalog {
    /// Installs a complete mixed provider definition without allocating native owners.
    ///
    /// Portable selections can subsequently name this exact complete definition.
    /// They cannot install providers, join singleton worlds, change connections
    /// or reuse the definition for another execution. Actual preparation uses
    /// the existing single-slot mixed-world source and behavioral barriers.
    ///
    /// # Errors
    /// Refuses a missing registry or world source, changed or incomplete provider
    /// partition, foreign selector/owner, mismatched activation, replacement of
    /// an existing definition, more than 64 definitions, or more than 16 MiB of
    /// aggregate serialized definition data.
    ///
    /// # Panics
    /// Installed source callbacks may unwind. Installation owns no native child
    /// or world custody slot and leaves the definition table unchanged on unwind.
    pub fn install_mixed_vendor_world(
        &mut self,
        request: InstalledMixedVendorWorldRequest,
    ) -> Result<(), NodeObservedError> {
        if self.mixed_vendor_worlds.len() >= MAXIMUM_DEFINITIONS {
            return Err(refused("mixed vendor definition count exhausted"));
        }
        let key = selection_key(&request.selections)?;
        if self.mixed_vendor_worlds.contains_key(&key) {
            return Err(refused("mixed vendor definition cannot be replaced"));
        }
        validate_roster(&request)?;
        let mut credit = MetadataCredit(MAXIMUM_DEFINITION_BYTES);
        credit.consume(&key)?;
        credit.consume(&request.scenario)?;
        credit.consume(&request.contributions)?;
        // Credit the fixed 16-byte operational identity without requiring
        // serialization of the campaign execution identifier.
        credit.consume(&(
            request.execution.as_bytes(),
            &request.activation.activation_id,
            &request.activation.world_binding_hash,
            request.activation.generation,
            request.activation.boundary,
            &request.activation.owners,
            request.runtime_limits.maximum_nodes,
            request.runtime_limits.maximum_owners,
            request.runtime_limits.maximum_operations,
            request.runtime_limits.maximum_retained_outputs,
        ))?;
        let retained_bytes = MAXIMUM_DEFINITION_BYTES - credit.0;
        let total = self
            .mixed_vendor_worlds
            .values()
            .try_fold(retained_bytes, |total, original| {
                total.checked_add(original.retained_bytes)
            });
        if total.is_none_or(|bytes| bytes > MAXIMUM_DEFINITION_BYTES) {
            return Err(refused("mixed vendor definition metadata exhausted"));
        }

        let plan = ProviderPreparationPlan {
            descriptors: request.scenario.descriptors.clone(),
            bindings: request.scenario.compatibility.clone(),
        };
        let contributions: Vec<_> = request
            .contributions
            .iter()
            .map(InstalledVendorContribution::borrowed)
            .collect();
        // Validate the complete partition and installed routing before retaining
        // it. Full plan and currentness authentication still occur at birth.
        let registry = self
            .vendor_providers
            .as_ref()
            .ok_or_else(|| refused("mixed vendor registry not installed"))?;
        drop(
            registry
                .mixed_admission_evidence(&contributions, &plan)
                .map_err(native)?,
        );
        self.mixed_vendor_worlds.insert(
            key,
            Rc::new(InstalledMixedVendorWorld {
                contributions: request.contributions,
                scenario: request.scenario,
                execution: request.execution,
                activation: request.activation,
                runtime_limits: request.runtime_limits,
                retained_bytes,
            }),
        );
        Ok(())
    }
}

pub(super) fn selected(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
) -> Result<Option<Rc<InstalledMixedVendorWorld>>, NodeObservedError> {
    if selections.len() < 2
        || selections
            .iter()
            .any(|selected| !matches!(selected.kind, InstalledNodeKind::InstalledVendor { .. }))
    {
        return Ok(None);
    }
    let key = selection_key(selections)?;
    Ok(catalog.mixed_vendor_worlds.get(&key).map(Rc::clone))
}

pub(super) fn scenario(
    original: &InstalledMixedVendorWorld,
) -> Result<NodeScenario, NodeObservedError> {
    drop(original.scenario.canonical_bytes()?);
    Ok(original.scenario.clone())
}

pub(super) fn prepare(
    catalog: &mut InstalledNodeCatalog,
    original: &InstalledMixedVendorWorld,
    scenario: NodeScenario,
    execution: ExecutionId,
) -> Result<InstalledPreparedWorld, NodeObservedError> {
    if execution != original.execution
        || scenario.canonical_bytes()? != original.scenario.canonical_bytes()?
    {
        return Err(refused(
            "mixed vendor execution or complete scenario differs",
        ));
    }
    let contributions: Vec<_> = original
        .contributions
        .iter()
        .map(InstalledVendorContribution::borrowed)
        .collect();
    catalog.prepare_mixed_vendor_world(
        &contributions,
        scenario,
        &original.activation,
        original.runtime_limits,
    )
}

fn selection_key(selections: &[InstalledNodeSelection]) -> Result<Vec<u8>, NodeObservedError> {
    if selections.len() < 2 || selections.len() > ProviderRegistryLimits::default().nodes {
        return Err(refused(
            "mixed vendor selection count is outside its finite limit",
        ));
    }
    if selections
        .windows(2)
        .any(|pair| pair[0].node >= pair[1].node)
    {
        return Err(refused(
            "mixed vendor selections must have unique ordered nodes",
        ));
    }
    for selected in selections {
        selected.node.validate()?;
        selected.owner.validate()?;
        let InstalledNodeKind::InstalledVendor {
            provider,
            profile,
            configuration,
        } = &selected.kind
        else {
            return Err(refused(
                "mixed vendor selector requires an installed provider",
            ));
        };
        provider.validate()?;
        profile.validate()?;
        configuration.validate()?;
    }
    MetadataCredit(MAXIMUM_DEFINITION_BYTES).consume(&selections)?;
    Ok(serde_json::to_vec(selections)?)
}

fn validate_roster(request: &InstalledMixedVendorWorldRequest) -> Result<(), NodeObservedError> {
    drop(request.scenario.canonical_bytes()?);
    if request.contributions.len() < 2
        || request.contributions.len() > ProviderRegistryLimits::default().nodes
        || request.selections.len() != request.scenario.compatibility.len()
        || request.activation.world_binding_hash != request.scenario.world.identity()?
        || request.activation.owners.len() != request.scenario.owners.len()
        || request
            .activation
            .owners
            .iter()
            .zip(&request.scenario.owners)
            .any(|(actual, expected)| actual.owner != expected.owner.id)
    {
        return Err(refused(
            "mixed vendor complete roster or activation differs",
        ));
    }
    for (selected, binding) in request
        .selections
        .iter()
        .zip(&request.scenario.compatibility)
    {
        if selected.node != binding.node_id || selected.owner != binding.execution_owner.id {
            return Err(refused(
                "mixed vendor selector differs from complete node ownership",
            ));
        }
    }
    for contribution in &request.contributions {
        for node in &contribution.nodes {
            let index = request
                .selections
                .binary_search_by(|selected| selected.node.cmp(node))
                .map_err(|_| refused("mixed vendor contribution names a foreign selector"))?;
            let InstalledNodeKind::InstalledVendor {
                provider,
                profile,
                configuration,
            } = &request.selections[index].kind
            else {
                return Err(refused(
                    "mixed vendor contributor has no installed selector",
                ));
            };
            if provider != &contribution.provider
                || profile != &contribution.profile
                || configuration != &contribution.configuration
            {
                return Err(refused(
                    "mixed vendor contribution and portable selector differ",
                ));
            }
        }
    }
    Ok(())
}

// This counts serialized data, independently of native resource accounting.
struct MetadataCredit(usize);

impl MetadataCredit {
    fn consume(&mut self, value: &impl Serialize) -> Result<(), NodeObservedError> {
        serde_json::to_writer(self, value).map_err(native)
    }
}

impl Write for MetadataCredit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("mixed vendor metadata credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
