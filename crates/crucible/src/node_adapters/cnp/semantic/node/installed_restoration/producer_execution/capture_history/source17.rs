//! Checks real live Node custody before borrowing its Source17 projection.
//!
//! Original family counts remain cumulative through the independently retained
//! inherited Node edge. No count, equal reference or historical phase grants a
//! current claim; the defining parent already holds the real Node/Window loan.

use super::*;
use crate::node_adapters::cnp::{CnpSemanticSource, PacketCompleteSemanticSource};
use crate::node_admission::OriginalRestoredCaptureClaim;
use crate::node_contract::{RuntimeError, WorldActivation};
use crucible_node_contract::ContentRef;

impl OriginalRestoredSettledNodeHistoryView<'_> {
    /// Joins the actual settled Node, World, original caps and inherited edge.
    ///
    /// # Errors
    /// Refuses a partial Node, old16 observation, active Producer attempt,
    /// unequal local Source history population, another inherited Node object,
    /// original generic cap exhaustion or a different current World authority.
    pub(crate) fn authenticate_source17_projection_data(
        &self,
        source: &PacketCompleteSemanticSource,
        claim: &OriginalRestoredCaptureClaim<'_>,
        world: &WorldActivation,
        inherited: Option<&ContentRef>,
        local_producer_attempts: usize,
    ) -> Result<[usize; 5], RuntimeError> {
        let installation =
            <PacketCompleteSemanticSource as CnpSemanticSource>::installation(source);
        claim.authenticate_node_data(self.route, world)?;
        if self.route.node != installation.descriptor.id {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut source_owners = self
            .route
            .owners
            .iter()
            .filter(|owner| owner.owner == installation.owner.owner.id);
        let source_owner = source_owners.next().ok_or(RuntimeError::ForeignAuthority)?;
        if source_owners.next().is_some()
            || source_owner.incarnation != installation.binding.authority.incarnation_id
            || source_owner.generation != installation.binding.authority.owner_generation
            || world
                .record()
                .owners
                .iter()
                .filter(|owner| *owner == source_owner)
                .count()
                != 1
            || self
                .route
                .owners
                .iter()
                .any(|owner| !world.record().owners.contains(owner))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let installed = self.installed;
        let current = installed
            .activation
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?;
        let producer = &installed.producer_executions;
        if !installed.install_started
            || !installed.installed
            || !current.same_authority(world)
            || !self
                .base
                .active
                .as_ref()
                .is_some_and(|active| active.same_authority(world))
            || installation.world_binding_hash != world.record().world_binding_hash
            || !installed.observation_attempted
            || installed.observation.is_none()
            || installed.observation_return.is_none()
            || !installed.current_observations.is_empty()
            || producer.pending.is_some()
            || producer.attempts.len() != local_producer_attempts
            || producer
                .attempts
                .iter()
                .any(|attempt| attempt.stage != Stage::Verified)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Imported Inputs remain in installed/family custody. A new local
        // Input still lacks the paired modeled Source17 ledger and is refused.
        if !self.base.inputs.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let counts = [
            installed.operations.len(),
            self.base.operations.len(),
            producer.attempts.len(),
            installed.inputs.len(),
            self.base.inputs.len(),
        ];
        // This association can only be issued by the Initial15 constructor.
        // A retained settled17 family requires its distinct context and owner;
        // imported DATA cannot add one to this concrete association.
        if inherited.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        counts.into_iter().try_fold(0usize, |total, count| {
            total
                .checked_add(count)
                .filter(|n| *n <= installation.maximum_operations)
                .ok_or(RuntimeError::ResourceLimit)
        })?;
        Ok(counts)
    }
}
