//! Keeps signed originals, source inspection and every prepared model in one capsule.

use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
};

use crucible::{
    node_adapters::transcript::{
        AuthenticatedTranscript, TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE,
        TRANSCRIPT_ORIGINAL_LINEAGE_PROFILE, TRANSCRIPT_REPLAY_PROFILE, TranscriptArchive,
        TranscriptReplayNode,
    },
    node_admission::{AdmissionLimits, AdmissionRequest, AdmittedGraph, admit_graph},
    node_contract::{
        ActivationRecord, NodeRoute, PreparedRealization, RuntimeCustodySlot,
        RuntimeCustodySupervisor, RuntimeLimits, SimulationNode,
    },
};
use crucible_campaign::ExecutionId;
use crucible_node_contract::{ContentRef, Id, Validate};

use super::InstalledOriginalLineagePlan;
use crate::node_observed_executor::factory::{
    InstalledNodeCatalog, NodeObservedError, acceptance::SourceBindingPolicy, measure_executable,
    native, refused,
};
use crate::{node_qualification::BehavioralAdmissionEvidence, node_scenario::NodeRunConfiguration};

struct PreparationScope<'a> {
    authority: &'a super::InstalledOriginalLineageAuthority,
    acceptance: &'a super::super::super::acceptance::InstalledBehavioralAcceptance,
    host_identity: &'a ContentRef,
    host_executable: &'a std::path::Path,
    custody: &'a crucible::node_contract::RuntimeCustodyQueue,
}

const LIMITS: RuntimeLimits = RuntimeLimits {
    maximum_nodes: 3,
    maximum_owners: 3,
    maximum_operations: 65_536,
    maximum_retained_outputs: 65_536,
};

/// Owns an original once-only source inspection and inactive complete model roster.
///
/// No method issues common Ready or publishes a world. The capsule retains all
/// MAC-loaded originals, installed source evidence and failures. Its drop moves
/// every inactive model to the original whole-world slot before source custody
/// is released; deployment callers must retain it through actual reclamation.
#[must_use = "retain original source and inactive world through common readiness and reclamation"]
pub struct InstalledOriginalLineagePreparation {
    references: BTreeMap<Id, ContentRef>,
    configuration: NodeRunConfiguration,
    originals: BTreeMap<Id, AuthenticatedTranscript>,
    plan: Option<Box<dyn InstalledOriginalLineagePlan>>,
    graph: Option<AdmittedGraph>,
    activation: Option<ActivationRecord>,
    slot: Option<Box<dyn RuntimeCustodySlot>>,
    nodes: Vec<Box<dyn SimulationNode>>,
    realization: Option<PreparedRealization>,
    attempted: bool,
}

impl InstalledOriginalLineagePreparation {
    /// Reports inactive complete preparation, without claiming Ready or publication.
    pub fn is_prepared(&self) -> bool {
        self.realization.is_some()
    }

    /// Borrows the actual admitted target graph under retained source custody.
    pub fn graph(&self) -> Option<&AdmittedGraph> {
        self.graph.as_ref()
    }

    /// Borrows the actual planned activation without creating publisher authority.
    pub fn activation(&self) -> Option<&ActivationRecord> {
        self.activation.as_ref()
    }

    /// Borrows the installed source inspection retained for capture and restoration.
    pub fn source_plan(&self) -> Option<&dyn InstalledOriginalLineagePlan> {
        self.plan.as_deref()
    }

    /// Borrows every original MAC-authenticated source, including future data.
    pub fn originals(&self) -> &BTreeMap<Id, AuthenticatedTranscript> {
        &self.originals
    }

    /// Transfers inactive handles while this source-owning capsule stays retained.
    ///
    /// # Errors
    /// Refuses repeated transfer or unsuccessful preparation. The actual runtime
    /// must independently complete common Ready and authentic world publication.
    pub fn take_realization(&mut self) -> Result<PreparedRealization, NodeObservedError> {
        self.realization
            .take()
            .ok_or_else(|| refused("original-lineage realization unavailable"))
    }

    pub(super) fn retire(&mut self) {
        drop(self.realization.take());
        if let (Some(slot), Some(activation)) = (self.slot.take(), self.activation.as_ref()) {
            drop(PreparedRealization::new(
                std::mem::take(&mut self.nodes),
                activation.clone(),
                LIMITS,
                slot,
            ));
        }
    }

    fn prepare(
        &mut self,
        catalog: &PreparationScope<'_>,
        archive: &TranscriptArchive,
        execution: ExecutionId,
    ) -> Result<(), NodeObservedError> {
        if self.attempted {
            return Err(refused("original-lineage preparation already attempted"));
        }
        // Commit once-only intent before archive or installed callbacks can unwind.
        self.attempted = true;
        self.nodes.try_reserve_exact(3).map_err(native)?;
        for (actor, reference) in &self.references {
            let source = archive.load(reference).map_err(native)?;
            self.originals.insert(actor.clone(), source);
        }
        let authority = catalog.authority;
        self.plan = Some(authority.policy().inspect(
            &self.originals,
            &self.configuration,
            catalog.host_identity,
            execution,
        )?);
        let plan = self
            .plan
            .as_deref()
            .ok_or_else(|| refused("installed inspection absent"))?;
        validate_plan(plan, self, catalog)?;
        let installed = catalog.acceptance;
        let scoped = SourceBindingPolicy::new(installed.policy.as_ref(), plan.scenario());
        let evidence = BehavioralAdmissionEvidence::new(plan, &scoped, installed.limits);
        self.graph = Some(
            admit_graph(
                AdmissionRequest {
                    world: &plan.scenario().world,
                    descriptors: &plan.scenario().descriptors,
                    bindings: plan.bindings(),
                    owners: &plan.scenario().owners,
                    requirements: &plan.scenario().requirements,
                },
                &evidence,
                AdmissionLimits {
                    maximum_content_bytes: 256 * 1024 * 1024,
                    // Admission charges every actual artifact fetch occurrence separately.
                    // Unique archive bodies retain their independent 384 MiB ceiling.
                    maximum_total_content_bytes: usize::try_from(
                        catalog.host_identity.length.get(),
                    )
                    .map_err(native)?
                    .checked_mul(3)
                    .and_then(|bytes| bytes.checked_add(64 * 1024 * 1024))
                    .ok_or_else(|| refused("original target fetch credit overflow"))?,
                    ..AdmissionLimits::default()
                },
            )
            .map_err(native)?,
        );
        self.activation = Some(plan.activation().clone());
        self.slot = Some(
            catalog
                .custody
                .reserve_world(plan.activation(), LIMITS)
                .map_err(native)?,
        );
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| refused("admitted graph absent"))?;
        for (actor, source) in &self.originals {
            let binding = graph
                .binding(actor)
                .ok_or_else(|| refused("original actor binding absent"))?;
            let owner = plan
                .activation()
                .owners
                .iter()
                .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
                .ok_or_else(|| refused("original-lineage target owner absent"))?;
            let model = TranscriptReplayNode::prepare(
                source.clone(),
                graph,
                NodeRoute {
                    node: actor.clone(),
                    owners: vec![owner.clone()],
                },
                &source.transcript().origin.context,
                plan.replay_policy(),
            )
            .map_err(native)?;
            self.nodes.push(Box::new(model));
        }
        let activation = plan.activation().clone();
        let slot = self
            .slot
            .take()
            .ok_or_else(|| refused("original world reservation absent"))?;
        self.realization = Some(PreparedRealization::new(
            std::mem::take(&mut self.nodes),
            activation,
            LIMITS,
            slot,
        ));
        Ok(())
    }
}

impl Drop for InstalledOriginalLineagePreparation {
    fn drop(&mut self) {
        self.retire();
    }
}

fn validate_plan(
    plan: &dyn InstalledOriginalLineagePlan,
    owned: &InstalledOriginalLineagePreparation,
    catalog: &PreparationScope<'_>,
) -> Result<(), NodeObservedError> {
    let scenario = plan.scenario();
    if plan.original_references() != &owned.references
        || plan.configuration().format != owned.configuration.format
        || plan.configuration().version != owned.configuration.version
        || plan.configuration().horizon_ps != owned.configuration.horizon_ps
        || plan.configuration().maximum_rounds != owned.configuration.maximum_rounds
        || scenario.descriptors.len() != 3
        || scenario.compatibility.len() != 3
        || scenario.owners.len() != 3
        || plan.bindings().len() != 3
        || plan.activation().owners.len() != 3
        || plan.activation().world_binding_hash != scenario.world.identity()?
        || measure_executable(catalog.host_executable)? != *catalog.host_identity
    {
        return Err(refused("installed original-lineage target scope differs"));
    }
    let mut total = 0usize;
    for object in &scenario.content {
        total = total
            .checked_add(object.bytes.len())
            .ok_or_else(|| refused("target body credit overflow"))?;
        if object.bytes.len() > 256 * 1024 * 1024 || total > 384 * 1024 * 1024 {
            return Err(refused("target reconstruction body credit exceeded"));
        }
        object.reference.verify(&object.bytes)?;
    }
    for (actor, source) in &owned.originals {
        let binding = plan
            .bindings()
            .iter()
            .find(|binding| &binding.compatibility.node_id == actor)
            .ok_or_else(|| refused("installed target actor differs"))?;
        let compatibility = &binding.compatibility;
        if scenario
            .compatibility
            .iter()
            .find(|row| &row.node_id == actor)
            != Some(compatibility)
            || compatibility.execution_owner != compatibility.capture_owner
            || compatibility.implementation.artifacts.len() != 1
            || compatibility.implementation.artifacts[0].content != *catalog.host_identity
            || !scenario
                .content
                .iter()
                .any(|body| body.reference == *catalog.host_identity)
            || source.transcript().origin.route.node != *actor
        {
            return Err(refused("installed target host or original actor differs"));
        }
        for (id, version) in [
            (TRANSCRIPT_REPLAY_PROFILE, 1),
            (TRANSCRIPT_ORIGINAL_LINEAGE_PROFILE, 2),
            (TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE, 2),
        ] {
            if compatibility
                .operating_contract
                .facets
                .iter()
                .filter(|facet| facet.id.as_str() == id && facet.version == version)
                .count()
                != 1
            {
                return Err(refused(
                    "initial original-lineage continuation facets incomplete",
                ));
            }
        }
    }
    Ok(())
}

impl InstalledNodeCatalog {
    /// Prepares exactly three original actors under both independently installed authorities.
    ///
    /// Every refusal or unwind retains the same capsule in this catalog. A
    /// repeated execution never redispatches inspection. The archive signer is
    /// host-owned and authenticates before source decoding; it is not supplied
    /// by portable requests. Preparation returns no Ready or capture permission.
    ///
    /// # Errors
    /// Refuses missing authorities before archive reads, changed original refs,
    /// excessive source/body credits, failed behavioral acceptance, unknown
    /// source roles, exhausted complete custody or installed callback failure.
    pub fn prepare_original_lineage(
        &mut self,
        archive: &TranscriptArchive,
        execution: ExecutionId,
        references: BTreeMap<Id, ContentRef>,
        configuration: NodeRunConfiguration,
    ) -> Result<(), NodeObservedError> {
        self.require_original_lineage_authorities()?;
        if references.len() != 3 || self.original_lineage.used.contains(&execution) {
            return Err(refused(
                "original-lineage actor roster or once-only identity differs",
            ));
        }
        let total = references.values().try_fold(0u64, |sum, reference| {
            reference.validate()?;
            sum.checked_add(reference.length.get())
                .ok_or_else(|| refused("original source credit overflow"))
        })?;
        if total > 64 * 1024 * 1024 || self.original_lineage.used.len() >= 64 {
            return Err(refused("original-lineage finite source custody exhausted"));
        }
        self.original_lineage.used.insert(execution);
        self.original_lineage.preparations.insert(
            execution,
            InstalledOriginalLineagePreparation {
                references,
                configuration,
                originals: BTreeMap::new(),
                plan: None,
                graph: None,
                activation: None,
                slot: None,
                nodes: Vec::new(),
                realization: None,
                attempted: false,
            },
        );
        // Borrow disjoint installation fields; the capsule never leaves its map.
        // The map already owns it if archive or installed callbacks unwind.
        let scope = PreparationScope {
            authority: self
                .original_lineage
                .authority
                .as_ref()
                .ok_or_else(|| refused("original source authority absent"))?,
            acceptance: self
                .behavioral_acceptance
                .as_ref()
                .ok_or_else(|| refused("original behavioral acceptance absent"))?,
            host_identity: &self.host_identity,
            host_executable: &self.host_executable,
            custody: &self.custody,
        };
        let owned = self
            .original_lineage
            .preparations
            .get_mut(&execution)
            .ok_or_else(|| refused("original source capsule absent"))?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            owned.prepare(&scope, archive, execution)
        }));
        result.unwrap_or_else(|_| Err(refused("original-lineage installed preparation unwound")))
    }
}
