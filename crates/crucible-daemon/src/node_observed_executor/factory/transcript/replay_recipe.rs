//! Installed original-source selection and owned fresh replay preparation.
//!
//! A recipe owns authenticated signed source documents and the independently
//! regenerated installed source profile. It accepts no caller-supplied target
//! graph, proof labels, cursor snapshots, or replacement semantic identifiers.

use crucible::node_adapters::transcript::AuthenticatedTranscript;
use std::rc::Rc;

use super::*;

/// Owns an installed conditional replay selection for one complete original pair.
///
/// Selection preserves original input, clock, connection and controller context.
/// Preparing it substitutes the replay implementation and fresh operational
/// owners only. Its nondeterministic physical origin remains in the whole-world
/// guarantees; the recipe grants no counterfactual or minimization permission.
pub struct InstalledReplayRecipe {
    source: source_enrollment::VerifiedRecordedWorld,
}

/// Owns a prepared replay world and its original semantic request plan.
///
/// A complete reserved runtime custody slot retains these model nodes on failure.
/// The owning backend must durably copy the accepted original bodies before
/// activation and any replay response. Source archive paths need not stay live.
pub struct InstalledConditionalReplay {
    pub(crate) world: InstalledPreparedWorld,
    pub(crate) configuration: NodeRunConfiguration,
    pub(crate) activation: ActivationRecord,
    pub(crate) plan: replay_stepper::ReplayStepper,
    pub(crate) source_objects: BTreeMap<Id, InputPayload>,
    pub(crate) original_world: crucible_campaign::CampaignHash,
    pub(crate) source_context: crucible_campaign::CampaignHash,
}

impl InstalledNodeCatalog {
    /// Authenticates signed original sources against the actual installed pair.
    ///
    /// Every source retains its original full context and native enrollment
    /// receipt. The catalog independently measures its host and native companion
    /// and regenerates the selected source world before issuing this recipe.
    ///
    /// # Errors
    /// Refuses missing, changed or differently configured source actors, source
    /// enrollment or installed artifacts. This performs no replay response.
    pub fn select_conditional_replay(
        &self,
        sources: BTreeMap<Id, AuthenticatedTranscript>,
        configuration: &NodeRunConfiguration,
    ) -> Result<InstalledReplayRecipe, NodeObservedError> {
        Ok(InstalledReplayRecipe {
            source: source_enrollment::verify_original_world(self, sources, configuration)?,
        })
    }
}

impl InstalledReplayRecipe {
    /// Prepares a fresh complete replay model under a reserved owning world slot.
    ///
    /// The execution nonce names fresh operational authority. Original semantic
    /// requests, stage IDs, batch IDs and window IDs remain unchanged. This model
    /// preserves its own original cursor and custody independently of the source
    /// physical backend, whose preservation facet remains unsupported.
    ///
    /// # Errors
    /// Refuses changed installation, unsupported source trajectory, exhausted
    /// whole-world custody or fresh graph/model preparation failure.
    pub fn prepare(
        self,
        catalog: &InstalledNodeCatalog,
        execution: ExecutionId,
    ) -> Result<InstalledConditionalReplay, NodeObservedError> {
        let allocation = cursor_allocation::CursorAllocation::allocate_preserving(
            catalog,
            self.source,
            execution,
        )?;
        let plan = replay_stepper::ReplayStepper::new(allocation.source())?;
        let limits = RuntimeLimits {
            maximum_nodes: 2,
            maximum_owners: 2,
            maximum_operations: 65_536,
            maximum_retained_outputs: 65_536,
        };
        // Reserve the complete original model roster before any node exists.
        // A rejected realization transfers all prepared nodes to this slot.
        let slot = catalog
            .custody
            .reserve_world(&allocation.profile().record, limits)
            .map_err(native)?;
        let prepared = allocation.prepare()?;
        let graph = Rc::try_unwrap(prepared.graph)
            .map_err(|_| refused("fresh replay graph is unexpectedly borrowed"))?;
        let source_objects = allocation
            .source()
            .sources
            .iter()
            .map(|(node, source)| {
                (
                    node.clone(),
                    InputPayload {
                        reference: source.reference().clone(),
                        bytes: source.bytes().to_vec(),
                    },
                )
            })
            .collect();
        let original_world = crucible_campaign::CampaignHash::parse(
            &allocation.source().scenario.world.identity()?.digest,
        )?;
        let contexts = allocation
            .source()
            .sources
            .iter()
            .map(|(node, source)| {
                Ok((
                    node.clone(),
                    crucible::node_adapters::transcript::context_commitment(
                        &source.transcript().origin,
                    )
                    .map_err(native)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, NodeObservedError>>()?;
        let source_context = crucible_campaign::CampaignHash::parse(
            &canonical::json_hash(
                "crucible.installed-replay-world-preconditions.v1",
                &contexts,
            )?
            .digest,
        )?;
        Ok(InstalledConditionalReplay {
            world: InstalledPreparedWorld {
                scenario: prepared.scenario,
                graph,
                realization: PreparedRealization::new(
                    prepared.nodes,
                    prepared.record,
                    limits,
                    slot,
                ),
            },
            configuration: prepared.configuration,
            activation: allocation.profile().record.clone(),
            plan,
            source_objects,
            original_world,
            source_context,
        })
    }
}
