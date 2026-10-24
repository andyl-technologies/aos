//! Reopens installed CPU semantics beneath exact authored Compute demands.
//!
//! These source-owned qualifications bind a measured fixed SE model and its
//! original operation witnesses. They are not native execution, accepted-class,
//! readiness, or restoration authority. Actual preparation retains every gate.

use std::{collections::BTreeMap, rc::Rc};

use crucible_engine::node_admission::{ComputeRequirement, NodeCapabilityRequirement};
use crucible_node_format::{BindingCompatibility, Id, NodeDescriptor, WorldBinding};

use super::super::{
    InstalledGem5ClosedProfile, InstalledGem5Isa, InstalledNodeCatalog, InstalledNodeKind,
    InstalledNodeSelection, NodeObservedError, refused,
};
use crate::node_scenario::NodeScenario;

/// Names the fixed installed gem5 x86 SE architectural interpretation.
///
/// The identifier excludes arbitrary guests, full-system devices and other CPU
/// or memory models. The complete machine and device references remain required.
pub const GEM5_CLOSED_X86_COMPUTE: &str = "gem5/closed-se-x86_64/1";

/// Names the fixed installed gem5 ARM SE architectural interpretation.
///
/// This is the separately witnessed AArch64 guest of the same closed model;
/// it does not advertise arbitrary ARM devices or full-system parity.
pub const GEM5_CLOSED_ARM_COMPUTE: &str = "gem5/closed-se-aarch64/1";

/// Retains independently measured CPU scopes selected by original host code.
#[derive(Clone, Default)]
pub(super) struct ComputeQualifications {
    nodes: BTreeMap<Id, Rc<MeasuredGem5Compute>>,
}

// Issued only after the same measured source and original borrowed demand
// have passed complete scope validation; parsed/copy-equal data cannot mint it.
pub(super) struct ComputeDemandProof<'a> {
    source: &'a MeasuredGem5Compute,
    demand: &'a NodeCapabilityRequirement,
}

impl ComputeDemandProof<'_> {
    pub(super) fn authenticates(
        &self,
        kind: &InstalledNodeKind,
        demand: &NodeCapabilityRequirement,
    ) -> bool {
        std::ptr::eq(self.demand, demand)
            && matches!(kind, InstalledNodeKind::Gem5Closed { isa } if *isa == self.source.isa)
    }
}

fn isa_name(isa: InstalledGem5Isa) -> &'static str {
    match isa {
        InstalledGem5Isa::X86_64 => "x86_64",
        InstalledGem5Isa::Aarch64 => "aarch64",
    }
}

struct MeasuredGem5Compute {
    installed: Rc<InstalledGem5ClosedProfile>,
    isa: InstalledGem5Isa,
    owner: Id,
    descriptor: NodeDescriptor,
    compatibility: BindingCompatibility,
    demand: ComputeRequirement,
    world: WorldBinding,
}

impl ComputeQualifications {
    /// Regenerates the whole original candidate before retaining measured CPU scope.
    pub(super) fn install(
        catalog: &InstalledNodeCatalog,
        selections: &[InstalledNodeSelection],
        baseline: &NodeScenario,
        required: impl IntoIterator<Item = Id>,
    ) -> Result<Self, NodeObservedError> {
        let required: Vec<_> = required.into_iter().collect();
        if required.is_empty() {
            return Ok(Self::default());
        }
        if !super::policy::gem5_ordinary(selections)
            && !super::policy::gem5_storage_group(selections)
        {
            return Err(refused(
                "no installed Compute policy for this complete candidate",
            ));
        }

        // Only the measured source catalog constructs this interpretation. A
        // copied configuration or definition cannot enroll a CPU qualifier.
        let actual = catalog.scenario(selections)?;
        if actual.canonical_bytes()? != baseline.canonical_bytes()? {
            return Err(refused(
                "Compute source candidate changed during resolution",
            ));
        }
        let installed = InstalledGem5ClosedProfile::built_in()?;
        let mut nodes = BTreeMap::new();
        for node in required {
            let selected = selections
                .iter()
                .find(|selected| selected.node == node)
                .ok_or_else(|| refused("Compute scope omitted its original selection"))?;
            let InstalledNodeKind::Gem5Closed { isa } = selected.kind else {
                return Err(refused(
                    "selected node has no qualified Compute interpretation",
                ));
            };
            let descriptor = actual
                .descriptors
                .iter()
                .find(|descriptor| descriptor.id == node)
                .ok_or_else(|| refused("Compute source omitted its actual descriptor"))?
                .clone();
            let compatibility = actual
                .compatibility
                .iter()
                .find(|binding| binding.node_id == node)
                .ok_or_else(|| refused("Compute source omitted its actual binding"))?
                .clone();
            let capabilities: crucible_node_format::CapabilityProfile =
                super::policy::object(&actual, &compatibility.capabilities_ref)?;
            let demand = ComputeRequirement {
                architecture: Id::new(match isa {
                    InstalledGem5Isa::X86_64 => GEM5_CLOSED_X86_COMPUTE,
                    InstalledGem5Isa::Aarch64 => GEM5_CLOSED_ARM_COMPUTE,
                })?,
                machine_ref: compatibility.configuration_ref.clone(),
                devices_ref: capabilities.devices_ref,
            };
            let qualifier = Rc::new(MeasuredGem5Compute {
                installed: Rc::clone(&installed),
                isa,
                owner: selected.owner.clone(),
                descriptor,
                compatibility,
                demand,
                world: actual.world.clone(),
            });
            if nodes.insert(node, qualifier).is_some() {
                return Err(refused("Compute scope repeats an original node"));
            }
        }
        Ok(Self { nodes })
    }

    pub(super) fn definition(&self, node: &Id) -> Option<&ComputeRequirement> {
        self.nodes.get(node).map(|source| &source.demand)
    }

    /// Authenticates current source and the complete actual node/demand tuple.
    pub(super) fn authenticate<'a>(
        &'a self,
        scenario: &NodeScenario,
        selected: &InstalledNodeSelection,
        demand: &'a NodeCapabilityRequirement,
    ) -> Result<Option<ComputeDemandProof<'a>>, NodeObservedError> {
        let Some(compute) = &demand.compute else {
            return Ok(None);
        };
        let source = self
            .nodes
            .get(&demand.node)
            .ok_or_else(|| refused("Compute demand has no original measured semantic qualifier"))?;
        // Capability wrapping changes only the scenario root. Every actual
        // node/connection/ownership/coordinator/initialization selection remains
        // the same source-generated world, including identity-bearing extensions.
        let mut expected_world = source.world.clone();
        expected_world.scenario_ref = scenario.world.scenario_ref.clone();
        if expected_world != scenario.world
            || selected.node != demand.node
            || selected.owner != source.owner
            || !matches!(selected.kind, InstalledNodeKind::Gem5Closed { isa } if isa == source.isa)
            || scenario
                .descriptors
                .iter()
                .find(|node| node.id == demand.node)
                != Some(&source.descriptor)
            || scenario
                .compatibility
                .iter()
                .find(|binding| binding.node_id == demand.node)
                != Some(&source.compatibility)
            || compute.architecture != source.demand.architecture
            || compute.machine_ref != source.demand.machine_ref
            || compute.devices_ref != source.demand.devices_ref
        {
            return Err(refused(
                "Compute demand differs from its complete original source model",
            ));
        }

        for reference in [
            &source.descriptor.model_ref,
            &source.descriptor.configuration_ref,
            &source.descriptor.initialization_ref,
            &source.compatibility.profile_ref,
            &source.compatibility.capabilities_ref,
            &source.compatibility.guarantees_ref,
            &source.compatibility.operating_contract.policy_ref,
            &source.demand.devices_ref,
        ] {
            let original = scenario
                .content
                .iter()
                .find(|object| object.reference == *reference)
                .ok_or_else(|| refused("Compute source definition body is unavailable"))?;
            reference.verify(&original.bytes)?;
        }

        // The loader verifies fixed CPU/cache/memory/syscall restrictions,
        // measured source/patch/model/guest/controller/configuration artifacts
        // and the same ISA's native full-position/publication/receipt witnesses.
        // Presence of an executable or a provider Passed flag is insufficient.
        let current = InstalledGem5ClosedProfile::built_in()?;
        if current.document() != source.installed.document()
            || current.guest(isa_name(source.isa))?.content
                != source.installed.guest(isa_name(source.isa))?.content
        {
            return Err(refused(
                "installed Compute source or native witness scope changed",
            ));
        }
        Ok(Some(ComputeDemandProof { source, demand }))
    }
}

impl InstalledNodeCatalog {
    /// Reads the exact source-installed Compute definition for one selected CPU.
    ///
    /// The returned fields are demand data, not live or qualification authority.
    /// Resolution and preparation reopen the independently measured source and
    /// still require accepted classes, actual native custody and all-owner Ready.
    ///
    /// # Errors
    /// Refuses uninstalled sources, unsupported models, changed measurements,
    /// foreign nodes and any candidate without an exact source-owned CPU policy.
    pub fn installed_compute_requirement(
        &self,
        selections: &[InstalledNodeSelection],
        node: &Id,
    ) -> Result<ComputeRequirement, NodeObservedError> {
        let baseline = self.scenario(selections)?;
        let sources = ComputeQualifications::install(self, selections, &baseline, [node.clone()])?;
        sources
            .definition(node)
            .cloned()
            .ok_or_else(|| refused("selected node has no original Compute definition"))
    }
}
