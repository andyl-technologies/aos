//! Fallible model copies under the caller's original decode resource custody.
//!
//! Runtime decision and schedule copies reserve concrete owned fields directly.
//! Artifact copies count their borrowed canonical output before admitting codec
//! scratch and decoded ownership. Neither path estimates heap from wire size.

use super::*;

mod decision;
pub(super) use decision::{copy_string, copy_vec, reserve_vec};

impl Schedule {
    /// Copies a schedule after admitting its concrete decision storage and fields.
    ///
    /// # Errors
    /// Refuses exhausted original metadata authority or allocation failure.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        let budget = crate::owned_decode::current_child_budget()
            .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
        let _scope = budget
            .as_ref()
            .map(crate::owned_decode::DecodeBudget::enter);
        let custody = budget
            .as_ref()
            .map(crate::owned_decode::DecodeBudget::custody)
            .unwrap_or_default();
        Ok(Self {
            decisions: copy_decisions(self.decisions(), self.len())?,
            _decode_custody: custody,
        })
    }

    /// Appends one moved decision after admitting the complete copied schedule.
    ///
    /// # Errors
    /// Refuses exhausted original resources, allocation failure, or count overflow.
    /// It preserves runtime decisions without imposing artifact codec limits.
    pub fn appended_admitted(&self, decision: Decision) -> Result<Self, EngineError> {
        let budget = crate::owned_decode::current_child_budget()
            .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
        let _scope = budget
            .as_ref()
            .map(crate::owned_decode::DecodeBudget::enter);
        let custody = budget
            .as_ref()
            .map(crate::owned_decode::DecodeBudget::custody)
            .unwrap_or_default();
        let length = self
            .len()
            .checked_add(1)
            .ok_or_else(|| scenario_serialization_error("schedule decision count overflow"))?;
        let mut decisions = copy_decisions(self.decisions(), length)?;
        decisions.push(decision);
        Ok(Self {
            decisions,
            _decode_custody: custody,
        })
    }

    /// Copies a prefix after admitting its concrete decision storage and fields.
    ///
    /// # Errors
    /// Refuses a prefix longer than the schedule, exhausted original authority,
    /// or allocation failure.
    pub fn prefix_admitted(&self, length: usize) -> Result<Self, EngineError> {
        let budget = crate::owned_decode::current_child_budget()
            .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
        let _scope = budget
            .as_ref()
            .map(crate::owned_decode::DecodeBudget::enter);
        let custody = budget
            .as_ref()
            .map(crate::owned_decode::DecodeBudget::custody)
            .unwrap_or_default();
        let decisions = self.decisions().get(..length).ok_or_else(|| {
            scenario_serialization_error("admitted schedule prefix exceeds the retained schedule")
        })?;
        Ok(Self {
            decisions: copy_decisions(decisions, length)?,
            _decode_custody: custody,
        })
    }

    /// Encodes canonical bytes after admitting an exact output buffer.
    ///
    /// # Errors
    /// Refuses exhausted original metadata authority, encoding overflow, or
    /// allocation failure before constructing the output buffer.
    pub fn to_compact_binary_admitted(&self) -> Result<Vec<u8>, EngineError> {
        ScenarioBinaryWriter::encode_admitted(SCHEDULE_BINARY_MAGIC_V4, |writer| {
            write_schedule_binary(self, writer);
        })
    }
}

impl Configuration {
    /// Copies a configuration with admitted concrete schedule ownership.
    ///
    /// # Errors
    /// Returns the same resource and allocation refusals as
    /// [`Schedule::try_clone_admitted`].
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        Ok(Self {
            def: self.def.clone(),
            schedule: self.schedule.try_clone_admitted()?,
        })
    }
}

impl Checkpoint {
    /// Copies a checkpoint with admitted canonical scratch and decoded field ownership.
    ///
    /// # Errors
    /// Refuses exhausted original authority, allocation failure, or malformed
    /// canonical checkpoint data before publishing the copied checkpoint.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        let bytes = ScenarioBinaryWriter::encode_admitted(CHECKPOINT_BINARY_MAGIC_V6, |writer| {
            write_checkpoint_binary(self, writer);
        })?;
        Self::from_compact_binary(&bytes)
    }
}

impl Predicate {
    /// Copies a predicate with admitted canonical scratch and decoded field ownership.
    ///
    /// # Errors
    /// Refuses exhausted original authority, allocation failure, or malformed
    /// predicate fields before publishing the copied predicate.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        let bytes = ScenarioBinaryWriter::encode_admitted(PREDICATE_BINARY_MAGIC, |writer| {
            write_predicate_binary(self, writer);
        })?;
        Self::from_compact_binary(&bytes)
    }
}

impl World {
    pub(super) fn clone_admitted(&self) -> Result<Self, EngineError> {
        let bytes = ScenarioBinaryWriter::encode_admitted(WORLD_BINARY_MAGIC_V6, |writer| {
            write_world_binary(self, writer);
        })?;
        Self::from_compact_binary(&bytes)
    }
}

impl Plan {
    pub(super) fn clone_admitted_for_world(&self, world: &World) -> Result<Self, EngineError> {
        let bytes = ScenarioBinaryWriter::encode_admitted(PLAN_BINARY_MAGIC, |writer| {
            write_plan_binary(self, writer);
        })?;
        let mut reader = ScenarioBinaryReader::new(&bytes, PLAN_BINARY_MAGIC)?;
        let plan = read_plan_binary_for_scenario(world, &mut reader)?;
        reader.finish()?;
        Ok(plan)
    }
}

impl Properties {
    pub(super) fn clone_admitted_for_world(&self, world: &World) -> Result<Self, EngineError> {
        let bytes = ScenarioBinaryWriter::encode_admitted(PROPERTIES_BINARY_MAGIC, |writer| {
            write_properties_binary(self, writer);
        })?;
        Self::from_compact_binary_for_world(world, &bytes)
    }
}

impl MeasurementDefinitions {
    pub(super) fn clone_admitted_for_context(
        &self,
        world: &World,
        plan: &Plan,
        properties: &Properties,
    ) -> Result<Self, EngineError> {
        let definitions = crate::owned_decode::from_json_slice(self.canonical_bytes())
            .map_err(|error| artifact_decode_error("copy measurement definitions", error))?;
        Self::from_decoded_definitions(world, plan, properties, definitions)
    }
}

impl ScenarioDefForm {
    /// Copies validated scenario components under original admitted resource custody.
    ///
    /// # Errors
    /// Refuses original resource exhaustion, codec allocation failure, or
    /// malformed or drifted canonical components.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        let bytes = self.to_compact_binary_admitted()?;
        Self::from_compact_binary(&bytes)
    }

    /// Encodes canonical bytes after counting and admitting an exact output buffer.
    ///
    /// # Errors
    /// Refuses exhausted original authority, size overflow, or allocation failure.
    pub fn to_compact_binary_admitted(&self) -> Result<Vec<u8>, EngineError> {
        ScenarioBinaryWriter::encode_admitted(SCENARIO_FORM_BINARY_MAGIC_V9, |writer| {
            write_scenario_form_binary(self, writer);
        })
    }
}

fn copy_decisions(source: &[Decision], capacity: usize) -> Result<Vec<Decision>, EngineError> {
    let mut decisions = reserve_vec(capacity)?;
    for decision in source {
        decisions.push(decision.try_clone_admitted()?);
    }
    Ok(decisions)
}

#[cfg(test)]
mod tests;

impl AssertionDef {
    /// Copies an assertion after admitting its names and predicate fields.
    ///
    /// # Errors
    /// Refuses exhausted original authority or a fallible predicate copy.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        let property = match &self.property {
            Property::Always { predicate } => Property::Always {
                predicate: predicate.try_clone_admitted()?,
            },
            Property::Sometimes { predicate } => Property::Sometimes {
                predicate: predicate.try_clone_admitted()?,
            },
            Property::Eventually {
                trigger,
                property,
                deadline,
            } => Property::Eventually {
                trigger: trigger.try_clone_admitted()?,
                property: property.try_clone_admitted()?,
                deadline: *deadline,
            },
            Property::AfterQuiescence { predicate } => Property::AfterQuiescence {
                predicate: predicate.try_clone_admitted()?,
            },
            Property::Reachable {
                predicate,
                expectation,
            } => Property::Reachable {
                predicate: predicate.try_clone_admitted()?,
                expectation: expectation.clone(),
            },
        };
        Ok(Self {
            id: AssertionId {
                name: copy_string(&self.id.name)?,
            },
            message: copy_string(&self.message)?,
            property,
        })
    }
}
