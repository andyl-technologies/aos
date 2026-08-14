//! Strict, flat TOML authoring projection for signal programs and bindings.
//!
//! Persistence uses [`FaultSignalPlanWire`], which deliberately mirrors the
//! internal typed contracts. The user-facing scenario format is different: it
//! presents one flat `[[plan.signal]]` graph and flat mapping, selector, and
//! effect tables. This module is the only conversion boundary between those
//! representations. Every decoded row is rebuilt through the ordinary typed
//! constructors; no authored identity or cached validation result is trusted.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    World, WorldFaultTargetRef, WorldIoNodeKind, WorldNetworkPathHop, WorldStorageKind,
    format_content_hash_ref,
};

use super::wire::toml_codec::{from_toml_value, to_toml_value};
use super::*;

mod error;

pub(crate) use error::FaultSignalAuthoringError;

/// Canonical TOML projection of one complete fault-signal layer.
pub(crate) struct FaultSignalAuthoringRows {
    /// Exact signal semantic version.
    pub(crate) semantic_version: u16,
    /// One scenario-owned resource declaration for the flat signal graph.
    pub(crate) resource_limits: FaultResourceLimits,
    /// Flat signal rows in canonical graph order.
    pub(crate) signals: Vec<toml::Value>,
    /// Flat binding rows in canonical binding-ID order.
    pub(crate) bindings: Vec<toml::Value>,
}

impl FaultSignalAuthoringRows {
    /// Projects a validated plan into the strict public authoring grammar.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalAuthoringError`] when an internal typed value cannot
    /// be represented, or when a plan contains multiple independently bounded
    /// programs. Public scenario TOML owns one flat graph; multi-program wire
    /// layouts remain valid only as an internal persistence representation.
    pub(crate) fn from_plan(plan: &FaultSignalPlan) -> Result<Self, FaultSignalAuthoringError> {
        let (nodes, exports) = match plan.programs() {
            [] => (Vec::new(), BTreeSet::new()),
            [program] => (
                program.nodes().to_vec(),
                program.exported_outputs().iter().cloned().collect(),
            ),
            programs => {
                return Err(FaultSignalAuthoringError::MultiplePrograms {
                    actual: programs.len(),
                });
            }
        };
        Ok(Self {
            semantic_version: FAULT_SIGNAL_PLAN_WIRE_VERSION,
            resource_limits: plan.resource_limits(),
            signals: nodes
                .iter()
                .map(|node| signal_to_toml(node, exports.contains(&node.id)))
                .collect::<Result<Vec<_>, _>>()?,
            bindings: plan
                .bindings()
                .iter()
                .map(|binding| binding_to_toml(&FaultBindingWire::from_binding(binding)))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    /// Parses and admits the strict public authoring grammar.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalAuthoringError`] for an unsupported semantic
    /// version, malformed or unknown fields, invalid graph, invalid binding, or
    /// final plan admission failure.
    pub(crate) fn admit(self, world: &World) -> Result<FaultSignalPlan, FaultSignalAuthoringError> {
        if self.semantic_version != FAULT_SIGNAL_PLAN_WIRE_VERSION {
            return Err(FaultSignalAuthoringError::Version {
                expected: FAULT_SIGNAL_PLAN_WIRE_VERSION,
                actual: self.semantic_version,
            });
        }
        validate_authoring_row_bounds(&self.signals, &self.bindings, self.resource_limits)?;
        if self.signals.is_empty() {
            if self.bindings.is_empty() {
                let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), self.resource_limits)
                    .map_err(FaultSignalAuthoringError::Plan)?;
                plan.validate_for_world(world)?;
                return Ok(plan);
            }
            return Err(FaultSignalAuthoringError::BindingsWithoutSignals);
        }

        let declared_shapes = declared_signal_shapes(&self.signals)?;
        let parsed = self
            .signals
            .into_iter()
            .map(|row| signal_from_toml(row, &declared_shapes))
            .collect::<Result<Vec<_>, _>>()?;
        let (nodes, exports): (Vec<_>, Vec<_>) = parsed
            .into_iter()
            .map(|(node, exported)| {
                let export = exported.then(|| node.id.clone());
                (node, export)
            })
            .unzip();
        let exports = exports.into_iter().flatten().collect();
        validate_world_signal_references(&nodes, world)?;
        let signal_limits = self
            .resource_limits
            .signal_limits()
            .map_err(FaultSignalAuthoringError::ResourceLimit)?;
        let program = SignalProgram::new(nodes, exports, signal_limits)
            .map_err(FaultSignalAuthoringError::Program)?;
        let bindings = self
            .bindings
            .into_iter()
            .map(|row| binding_from_toml(row, &program, world))
            .collect::<Result<Vec<_>, _>>()?;
        let plan = FaultSignalPlan::new(vec![program], bindings, self.resource_limits)
            .map_err(FaultSignalAuthoringError::Plan)?;
        plan.validate_for_world(world)?;
        Ok(plan)
    }
}

mod binding_codec;
mod effect_codec;
mod signal_codec;
mod target_resolution;
mod world_validation;

pub(super) use binding_codec::validate_selector_for_world;
use binding_codec::{binding_from_toml, binding_to_toml};
use effect_codec::*;
use signal_codec::*;
use target_resolution::*;
use world_validation::*;
