//! Incremental inactive participants beneath one preowned original world slot.
//!
//! The builder preserves partial native custody without granting source, class,
//! graph, readiness or execution authority. Mixed contributors borrow the same
//! capsule and never receive a second world slot or extract another's handles.

use crucible_node_format::Validate;

use crate::node_admission::EvidenceError;

use super::{
    ActivationRecord, OriginalRealizationRequest, PreparedRealization, ProviderPreparationPlan,
    ProviderRegistryLimits, RealizationFailure, RuntimeCustodySlot, RuntimeLimits, SimulationNode,
};

/// Collects finite original participants without extracting their native handles.
///
/// Providers form this capsule before their first native allocation. Adopted
/// participants remain under its same supervision slot on failure or unwind.
/// Partial birth before append remains the contributor's guarded responsibility.
#[must_use = "finish the original world or retain its complete partial custody"]
pub struct ProviderWorldPreparation<'a> {
    pub(super) original: PreparedRealization,
    plan: &'a ProviderPreparationPlan,
    positions: Vec<usize>,
    metadata_remaining: usize,
    refused: bool,
}

impl<'a> ProviderWorldPreparation<'a> {
    /// Preallocates participant storage for one installed provider's whole world.
    ///
    /// # Errors
    /// Refuses invalid finite rosters, metadata ceilings, allocation or the
    /// original world slot. This method creates no native participant.
    ///
    /// # Panics
    /// The slot validator may unwind after the complete empty capsule is formed.
    pub fn new(request: OriginalRealizationRequest<'a>) -> Result<Self, RealizationFailure> {
        if request.selection.nodes.len() != request.plan.descriptors.len()
            || request
                .plan
                .descriptors
                .iter()
                .zip(request.selection.nodes)
                .any(|(descriptor, node)| &descriptor.id != node)
        {
            return Err(RealizationFailure {
                reason: "provider preparation changes its original selection".into(),
                retained: None,
            });
        }
        Self::for_world(
            request.plan,
            request.activation,
            request.runtime_limits,
            request.selection.limits,
            request.custody_slot,
        )
    }

    /// Reserves one complete world before any of its contributors can construct.
    ///
    /// Participant and index storage include one borrowed rejection and one
    /// final consuming rejection. Actual metadata debit is cumulative across
    /// all contributors. This method accepts planning data only; source and class
    /// authentication remain mandatory in the registry and common admission.
    ///
    /// # Errors
    /// Refuses incomplete or unordered plans, excessive finite metadata, storage
    /// failure or a foreign world slot, preserving that slot after its callback.
    ///
    /// # Panics
    /// Slot validation may unwind. The complete capsule already owns the slot.
    pub fn for_world(
        plan: &'a ProviderPreparationPlan,
        activation: &ActivationRecord,
        runtime_limits: RuntimeLimits,
        limits: ProviderRegistryLimits,
        custody_slot: Box<dyn RuntimeCustodySlot>,
    ) -> Result<Self, RealizationFailure> {
        let maximum = ProviderRegistryLimits::default();
        let fail = |reason: &str| RealizationFailure {
            reason: reason.into(),
            retained: None,
        };
        if plan.descriptors.is_empty()
            || limits.nodes == 0
            || limits.nodes > maximum.nodes
            || plan.descriptors.len() > limits.nodes
            || plan.bindings.len() != plan.descriptors.len()
            || plan
                .descriptors
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || activation.owners.is_empty()
            || activation.owners.len() > maximum.nodes
            || limits.metadata_bytes == 0
            || limits.metadata_bytes > maximum.metadata_bytes
        {
            return Err(fail(
                "provider preparation lacks a finite complete original plan",
            ));
        }
        super::installed_provider::credit(
            &(
                plan,
                &activation.activation_id,
                &activation.world_binding_hash,
                activation.boundary,
                &activation.owners,
            ),
            limits.metadata_bytes,
        )
        .map_err(|error| fail(&error.message))?;
        for (descriptor, binding) in plan.descriptors.iter().zip(&plan.bindings) {
            descriptor
                .validate()
                .map_err(|error| fail(&error.to_string()))?;
            binding
                .validate()
                .map_err(|error| fail(&error.to_string()))?;
            if binding.node_id != descriptor.id
                || binding.descriptor_hash
                    != descriptor
                        .identity()
                        .map_err(|error| fail(&error.to_string()))?
            {
                return Err(fail("provider preparation changes its original node plan"));
            }
        }
        let capacity = plan
            .descriptors
            .len()
            .checked_add(2)
            .ok_or_else(|| fail("provider participant capacity overflow"))?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(capacity)
            .map_err(|_| fail("provider participant storage unavailable"))?;
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(capacity)
            .map_err(|_| fail("provider index storage unavailable"))?;
        let original =
            PreparedRealization::new(nodes, activation.clone(), runtime_limits, custody_slot);
        let preparation = Self {
            original,
            plan,
            positions,
            metadata_remaining: limits.metadata_bytes,
            refused: false,
        };
        let validation = match preparation.original.custody_slot.as_ref() {
            Some(slot) => {
                slot.validate_world(preparation.original.activation_record(), runtime_limits)
            }
            None => return Err(preparation.fail("provider original world slot is absent")),
        };
        if let Err(error) = validation {
            return Err(preparation.fail(&error.to_string()));
        }
        Ok(preparation)
    }

    /// Adopts the next sequential participant before inspecting its callbacks.
    ///
    /// # Errors
    /// Retains every original, including a rejected participant, on metadata or
    /// route mismatch. This consuming convenience API is for a single provider.
    ///
    /// # Panics
    /// Getters may unwind; the adopted node remains in the complete world capsule.
    pub fn append(mut self, node: Box<dyn SimulationNode>) -> Result<Self, RealizationFailure> {
        let index = self.original.nodes.len();
        let mut original = Some(node);
        if let Err(error) = self.append_original(index, &mut original) {
            if let Some(node) = original.take() {
                // A consuming rejection must retain its supplied original too.
                // for_world reserves this final position before any native birth.
                self.original.nodes.push(node);
            }
            return Err(self.fail(&error.message));
        }
        Ok(self)
    }

    /// Borrows shared preparation and adopts one original at its declared index.
    ///
    /// The caller retains `original` until this method takes it. Once adopted,
    /// the original enters the world capsule before any getter. A failed or
    /// unwound metadata check permanently refuses this builder. Further calls
    /// leave their supplied node untouched; they cannot allocate another slot.
    ///
    /// # Errors
    /// Refuses absent nodes, repeated indices, exhausted storage, prior refusal,
    /// foreign metadata or routes. Adopted originals remain in this builder;
    /// originals not taken remain in the caller's slot.
    ///
    /// # Panics
    /// Participant getters may unwind after adoption. The same builder must
    /// remain owned outside the contributor callback and its unwind boundary.
    pub fn append_original(
        &mut self,
        index: usize,
        original: &mut Option<Box<dyn SimulationNode>>,
    ) -> Result<(), EvidenceError> {
        let error = |message: &str| EvidenceError {
            message: message.into(),
        };
        if self.refused || self.original.nodes.len() > self.plan.descriptors.len() {
            return Err(error("original world preparation is already refused"));
        }
        let Some(node) = original.take() else {
            return Err(error("original contributor participant is absent"));
        };
        // Both vectors were reserved before any contributor. Refusal is sticky
        // before getters so an unwind cannot resume appending to partial custody.
        self.original.nodes.push(node);
        self.positions.push(index);
        self.refused = true;
        let Some(expected) = self.plan.descriptors.get(index) else {
            return Err(error(
                "contributor appended an unplanned original participant",
            ));
        };
        if self.positions[..self.positions.len() - 1].contains(&index) {
            return Err(error("contributor repeats an original participant index"));
        }
        let actual = &self.original.nodes[self.original.nodes.len() - 1];
        let descriptor = actual.descriptor();
        let binding = actual.binding();
        let route = actual.route();
        let bytes = super::installed_provider::measured_credit(
            &(descriptor, binding, route),
            self.metadata_remaining,
        )?;
        self.metadata_remaining -= bytes;
        if descriptor != expected
            || binding.compatibility != self.plan.bindings[index]
            || route.node != expected.id
            || route.owners.is_empty()
            || route.owners.windows(2).any(|pair| pair[0] >= pair[1])
            || route
                .owners
                .iter()
                .any(|owner| !self.original.activation.owners.contains(owner))
        {
            return Err(error(
                "contributor original differs from accepted world planning",
            ));
        }
        self.refused = false;
        Ok(())
    }

    /// Borrows the same complete activation without granting an execution barrier.
    pub fn activation_record(&self) -> &ActivationRecord {
        self.original.activation_record()
    }

    /// Borrows actual adopted nodes without removing any custody from the world.
    pub fn participants(&self) -> impl ExactSizeIterator<Item = &dyn SimulationNode> {
        self.original.participants()
    }

    /// Returns the complete capsule in its original declared node order.
    ///
    /// Reordering uses the already reserved indices and no new participant
    /// storage. Graph admission and all-owner activation remain mandatory next.
    ///
    /// # Errors
    /// Preserves every adopted original on refusal or incomplete preparation.
    pub fn finish(mut self) -> Result<PreparedRealization, RealizationFailure> {
        if self.refused || self.original.nodes.len() != self.plan.descriptors.len() {
            return Err(self.fail("provider preparation omits or rejects original participants"));
        }
        for index in 0..self.positions.len() {
            while self.positions[index] != index {
                let destination = self.positions[index];
                self.original.nodes.swap(index, destination);
                self.positions.swap(index, destination);
            }
        }
        Ok(self.original)
    }

    pub(super) fn fail(self, reason: &str) -> RealizationFailure {
        RealizationFailure {
            reason: reason.into(),
            retained: Some(Box::new(self.original)),
        }
    }
}

/// Borrows only one accepted contributor's append path into the global capsule.
///
/// The registry constructs this view after whole-world source authentication.
/// A contributor cannot replace the world builder, extract participants or
/// replace its original slot. It appends only its declared local node order.
pub struct ProviderWorldContribution<'world, 'plan> {
    world: &'world mut ProviderWorldPreparation<'plan>,
    local: &'world ProviderPreparationPlan,
    next: usize,
}

impl<'world, 'plan> ProviderWorldContribution<'world, 'plan> {
    pub(super) fn new(
        world: &'world mut ProviderWorldPreparation<'plan>,
        local: &'world ProviderPreparationPlan,
    ) -> Self {
        Self {
            world,
            local,
            next: 0,
        }
    }

    /// Adopts the next accepted local original before inspecting any node getter.
    ///
    /// The index comes from the accepted partition, rather than provider input.
    /// The original remains in the caller's slot until taken into the global
    /// capsule. On validation refusal that capsule retains it permanently.
    ///
    /// # Errors
    /// Refuses excess, missing, foreign or changed participants and prior world
    /// refusal. Untaken originals remain caller-owned; taken originals remain
    /// beneath the registry's same global preparation.
    ///
    /// # Panics
    /// Metadata getters may unwind after adoption. The registry retains the
    /// complete builder outside this view and the provider callback boundary.
    pub fn append_original(
        &mut self,
        original: &mut Option<Box<dyn SimulationNode>>,
    ) -> Result<(), EvidenceError> {
        let expected = self
            .local
            .descriptors
            .get(self.next)
            .ok_or_else(|| EvidenceError {
                message: "contributor exceeds its accepted local node roster".into(),
            })?;
        let index = self
            .world
            .plan
            .descriptors
            .binary_search_by(|actual| actual.id.cmp(&expected.id))
            .map_err(|_| EvidenceError {
                message: "contributor node absent from global plan".into(),
            })?;
        let had_original = original.is_some();
        let result = self.world.append_original(index, original);
        if had_original && original.is_none() {
            self.next += 1;
        }
        result
    }

    /// Borrows the same original global activation without readiness authority.
    pub fn activation_record(&self) -> &ActivationRecord {
        self.world.activation_record()
    }
}
