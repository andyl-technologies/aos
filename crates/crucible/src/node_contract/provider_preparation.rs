//! Incremental inactive participants beneath one preowned original world slot.
//!
//! The builder preserves partial native custody without granting source, class,
//! graph, readiness or execution authority. The installed registry and ordinary
//! admission still authenticate the complete final realization.

use crucible_node_contract::Validate;

use super::{
    OriginalRealizationRequest, PreparedRealization, ProviderPreparationPlan,
    ProviderRegistryLimits, RealizationFailure, SimulationNode,
};

/// Collects finite original participants without extracting their native handles.
///
/// Providers construct this capsule before their first native allocation. Each
/// append consumes the capsule and adopts the original node before inspecting
/// callbacks. Dropping partial preparation transfers its complete native custody
/// to the same pre-reserved world supervisor.
#[must_use = "finish the original world or retain its complete partial custody"]
pub struct ProviderWorldPreparation<'a> {
    original: PreparedRealization,
    plan: &'a ProviderPreparationPlan,
    metadata_bytes: usize,
}

impl<'a> ProviderWorldPreparation<'a> {
    /// Preallocates participant storage before any original native construction.
    ///
    /// One additional reserved position holds a rejected append until the whole
    /// original failure is returned. No node is dropped merely for failing its
    /// descriptor, route or compatibility check.
    ///
    /// # Errors
    /// Refuses invalid finite rosters, metadata ceilings, allocation or the
    /// original world slot. This method creates no native participant.
    ///
    /// # Panics
    /// The installed slot validator may unwind. The already formed capsule
    /// retains the same empty native preparation and its original world slot.
    pub fn new(request: OriginalRealizationRequest<'a>) -> Result<Self, RealizationFailure> {
        let maximum = ProviderRegistryLimits::default();
        let selected = request.selection;
        let fail = |reason: &str| RealizationFailure {
            reason: reason.into(),
            retained: None,
        };
        if selected.nodes.is_empty()
            || selected.limits.nodes == 0
            || selected.limits.nodes > maximum.nodes
            || selected.nodes.len() > selected.limits.nodes
            || selected.nodes.windows(2).any(|pair| pair[0] >= pair[1])
            || request.plan.descriptors.len() != selected.nodes.len()
            || request.plan.bindings.len() != selected.nodes.len()
            || request.activation.owners.is_empty()
            || request.activation.owners.len() > maximum.nodes
            || selected.limits.metadata_bytes == 0
            || selected.limits.metadata_bytes > maximum.metadata_bytes
        {
            return Err(fail(
                "provider preparation lacks a finite complete original plan",
            ));
        }
        super::installed_provider::credit(
            &(
                request.plan,
                &request.activation.activation_id,
                &request.activation.world_binding_hash,
                request.activation.boundary,
                &request.activation.owners,
            ),
            selected.limits.metadata_bytes,
        )
        .map_err(|error| fail(&error.message))?;
        for ((descriptor, binding), node) in request
            .plan
            .descriptors
            .iter()
            .zip(&request.plan.bindings)
            .zip(selected.nodes)
        {
            descriptor
                .validate()
                .map_err(|error| fail(&error.to_string()))?;
            binding
                .validate()
                .map_err(|error| fail(&error.to_string()))?;
            if &descriptor.id != node
                || &binding.node_id != node
                || binding.descriptor_hash
                    != descriptor
                        .identity()
                        .map_err(|error| fail(&error.to_string()))?
            {
                return Err(fail("provider preparation changes its original node plan"));
            }
        }
        let capacity = selected
            .nodes
            .len()
            .checked_add(1)
            .ok_or_else(|| fail("provider participant capacity overflow"))?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(capacity)
            .map_err(|_| fail("provider participant storage unavailable"))?;
        let original = PreparedRealization::new(
            nodes,
            request.activation.clone(),
            request.runtime_limits,
            request.custody_slot,
        );
        let preparation = Self {
            original,
            plan: request.plan,
            metadata_bytes: selected.limits.metadata_bytes,
        };
        let validation = match preparation.original.custody_slot.as_ref() {
            Some(slot) => slot.validate_world(
                preparation.original.activation_record(),
                request.runtime_limits,
            ),
            None => return Err(preparation.fail("provider original world slot is absent")),
        };
        if let Err(error) = validation {
            return Err(preparation.fail(&error.to_string()));
        }
        Ok(preparation)
    }

    /// Adopts one original participant before validating its inactive metadata.
    ///
    /// # Errors
    /// Returns the complete original preparation, including this rejected node,
    /// for changed descriptors, bindings, routes, order or an extra participant.
    ///
    /// # Panics
    /// Participant getters may unwind. The adopted node and every prior node
    /// remain beneath the same world slot during supervised native cleanup.
    pub fn append(mut self, node: Box<dyn SimulationNode>) -> Result<Self, RealizationFailure> {
        let index = self.original.nodes.len();
        // new() reserves the complete accepted roster plus one rejected node.
        // Every rejection consumes this builder, so this never grows storage.
        self.original.nodes.push(node);
        let Some(expected) = self.plan.descriptors.get(index) else {
            return Err(self.fail("provider appended an unplanned original participant"));
        };
        let actual = &self.original.nodes[index];
        let route = actual.route();
        let valid = super::installed_provider::credit(
            &(actual.descriptor(), actual.binding(), route),
            self.metadata_bytes,
        )
        .is_ok()
            && actual.descriptor() == expected
            && actual.binding().compatibility == self.plan.bindings[index]
            && route.node == expected.id
            && !route.owners.is_empty()
            && route.owners.windows(2).all(|pair| pair[0] < pair[1])
            && route
                .owners
                .iter()
                .all(|owner| self.original.activation.owners.contains(owner));
        if !valid {
            return Err(self.fail("provider original participant differs from accepted planning"));
        }
        Ok(self)
    }

    /// Returns the same complete inactive capsule without granting readiness.
    ///
    /// # Errors
    /// Preserves partial native preparation when an original participant is
    /// missing. Complete graph admission and all-owner activation remain next.
    pub fn finish(self) -> Result<PreparedRealization, RealizationFailure> {
        if self.original.nodes.len() != self.plan.descriptors.len() {
            return Err(self.fail("provider preparation omits original participants"));
        }
        Ok(self.original)
    }

    fn fail(self, reason: &str) -> RealizationFailure {
        RealizationFailure {
            reason: reason.into(),
            retained: Some(Box::new(self.original)),
        }
    }
}
