//! Retains an inactive CPU lease for one complete signed four-owner source.
//!
//! The source and target remain whole-world records. The two-node installed CPU
//! policy authenticates its unchanged implementation separately; it never sees
//! a fabricated two-owner archive or authorizes the added storage participants.

use std::rc::Rc;

use crucible::{node_contract::ActivationRecord, node_state::NativeArchiveRecord};
use crucible_node_contract::{ContentRef, U64, canonical};

use super::super::super::{NodeObservedError, refused};
use super::super::{custody::Gem5CustodyQueue, profile::MixedProfile};
use super::profile::IndependentGroupProfile;
use crate::node_scenario::ScenarioContent;

/// Owns exact full-world source, fresh target and already reserved native custody.
pub(in crate::node_observed_executor::factory::native_state) struct ReservedGroupRestore {
    profile: Rc<IndependentGroupProfile>,
    source: NativeArchiveRecord,
    target: ActivationRecord,
    queue: Gem5CustodyQueue,
}

impl ReservedGroupRestore {
    /// Retains an independently selected profile and an actual inactive source lease.
    ///
    /// # Errors
    /// Refuses another world, incomplete or aliased owners, stale target identities
    /// and native custody that has already been used or names another archive.
    pub(in crate::node_observed_executor::factory::native_state) fn new(
        profile: Rc<IndependentGroupProfile>,
        source: NativeArchiveRecord,
        target: ActivationRecord,
        queue: Gem5CustodyQueue,
    ) -> Result<Self, NodeObservedError> {
        let reservation = Self {
            profile,
            source,
            target,
            queue,
        };
        reservation.verify()?;
        Ok(reservation)
    }

    pub(in crate::node_observed_executor::factory::native_state) fn verify(
        &self,
    ) -> Result<(), NodeObservedError> {
        let selected = &self.profile.scenario;
        if !self.profile.preserving
            || selected.owners.len() != 4
            || selected.descriptors.len() != 4
            || self.target.owners.len() != 4
            || self.source.owners().len() != 4
            || selected.world.identity()? != self.target.world_binding_hash
            || self.source.manifest().world_binding_hash != self.target.world_binding_hash
            || self.source.manifest().cut != self.target.boundary
        {
            return Err(refused("reserved group source or full target differs"));
        }
        let previous = self
            .source
            .source_activation()
            .map_err(|error| refused(&error.to_string()))?;
        if previous.world_binding_hash != self.target.world_binding_hash
            || previous.owners.len() != 4
            || previous.activation_id == self.target.activation_id
            || previous.generation.checked_add(U64::new(1))? != self.target.generation
            || self.target.owners.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(refused(
                "reserved group target is not a fresh original successor",
            ));
        }

        for selected_owner in &selected.owners {
            let original = previous
                .owners
                .iter()
                .find(|owner| owner.owner == selected_owner.owner.id)
                .ok_or_else(|| refused("reserved group original owner is absent"))?;
            let fresh = self
                .target
                .owners
                .iter()
                .find(|owner| owner.owner == selected_owner.owner.id)
                .ok_or_else(|| refused("reserved group fresh owner is absent"))?;
            if original.incarnation == fresh.incarnation
                || original.generation.checked_add(U64::new(1))? != fresh.generation
                || self
                    .target
                    .owners
                    .iter()
                    .filter(|owner| owner.incarnation == fresh.incarnation)
                    .count()
                    != 1
            {
                return Err(refused("reserved group owner identity is stale or aliased"));
            }
        }
        for binding in &selected.compatibility {
            let capture = self
                .source
                .owners()
                .iter()
                .find(|owner| owner.owner == binding.capture_owner.id)
                .ok_or_else(|| refused("reserved group signed capture owner is absent"))?;
            if self
                .source
                .owners()
                .iter()
                .filter(|owner| owner.owner == binding.capture_owner.id)
                .count()
                != 1
                || capture.participants.len() != 1
                || capture.participants[0] != binding.node_id
                || capture.cut != self.target.boundary
            {
                return Err(refused("reserved group signed capture roster differs"));
            }
        }
        let cpu = self
            .target
            .owners
            .iter()
            .find(|owner| owner.owner.as_str() == "owner/cpu")
            .ok_or_else(|| refused("reserved group original CPU is absent"))?;
        self.queue
            .verify_reserved_restore(&self.target, cpu, &self.source)
            .map_err(|error| refused(&error.to_string()))
    }

    /// Creates a finite receipt for the lease, explicitly without native readiness.
    ///
    /// # Errors
    /// Refuses changed installed CPU metadata, another complete world or a used lease.
    pub(in crate::node_observed_executor::factory::native_state) fn receipt(
        &self,
        native: &MixedProfile,
        clock: &ContentRef,
    ) -> Result<ScenarioContent, NodeObservedError> {
        self.verify()?;
        if native.scenario.canonical_bytes()? != self.profile.native.scenario.canonical_bytes()?
            || native.qualification != self.profile.native.qualification
        {
            return Err(refused("reserved group original CPU source differs"));
        }
        // Four owners and both regenerated source definitions were bounded before
        // reservation. This receipt records the actual lease; it grants no Ready.
        let body = canonical::canonical_json(&serde_json::json!({
            "schema": "crucible.independent-group-reserved-enrollment.v1",
            "world": self.target.world_binding_hash,
            "group_policy": self.profile.qualification,
            "native_source_world": native.scenario.world.identity()?,
            "native_policy": native.qualification,
            "package": native.installed.identity(),
            "clock": clock,
            "signed_source": self.source.artifact(),
            "activation": {
                "id": self.target.activation_id,
                "generation": self.target.generation,
                "cut": self.target.boundary,
                "owners": self.target.owners.iter().map(|owner| {
                    (&owner.owner, &owner.incarnation, owner.generation)
                }).collect::<Vec<_>>(),
            },
            "native_readiness": false,
        }))?;
        let reference = canonical::content_ref(&body, "application/json")?;
        Ok(ScenarioContent {
            reference,
            bytes: body,
        })
    }

    pub(in crate::node_observed_executor::factory::native_state) fn target(
        &self,
    ) -> &ActivationRecord {
        &self.target
    }
}
