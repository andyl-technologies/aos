//! Allocation admission for retained assertion definitions and diagnostic owners.
//!
//! Definitions and tables share one original account. Mutable passes and
//! checkpoints use independent children of that same authority; each returned
//! owner retains its child until its copied fields have closed.

use super::*;
use crate::owned_decode::{DecodeAdmissionError, charge_bytes, reserve_vec};
use serde::{Serialize, de::DeserializeOwned};

pub(in crate::trigger) fn admission(source: DecodeAdmissionError) -> EngineError {
    EngineError::ArtifactDecodeAdmission { source }
}

pub(in crate::trigger) fn reserve_arc<T>() -> Result<(), EngineError> {
    let bytes = std::mem::size_of::<T>()
        .checked_add(2 * std::mem::size_of::<usize>())
        .ok_or_else(|| admission(DecodeAdmissionError::new(AllocationSizeOverflow)))?;
    charge_bytes(bytes as u64).map_err(admission)
}

pub(in crate::trigger) fn copy_string(value: &str) -> Result<String, EngineError> {
    crate::owned_decode::display_string(value).map_err(admission)
}

pub(in crate::trigger) fn copy_node(value: &NodeId) -> Result<NodeId, EngineError> {
    Ok(NodeId {
        name: copy_string(&value.name)?,
    })
}

pub(in crate::trigger) fn copy_assertion_id(
    value: &AssertionId,
) -> Result<AssertionId, EngineError> {
    Ok(AssertionId {
        name: copy_string(&value.name)?,
    })
}

pub(in crate::trigger) fn reserve_slot<T>(values: &mut Vec<T>) -> Result<(), EngineError> {
    reserve_vec(values, 1).map_err(admission)
}

pub(in crate::trigger) fn copy_json<T: Serialize + DeserializeOwned>(
    value: &T,
) -> Result<T, EngineError> {
    copy_json_as(value)
}

pub(in crate::trigger) fn copy_json_as<T: DeserializeOwned, S: Serialize + ?Sized>(
    value: &S,
) -> Result<T, EngineError> {
    // The encoded image is temporary. Its independent child closes after the
    // typed copy, rather than accumulating scratch on a retained output bank.
    let encoded = crate::owned_decode::require_current_child_budget().map_err(admission)?;
    let bytes = {
        let _scope = encoded.enter();
        crate::owned_decode::to_json_vec(value).map_err(admission)?
    };
    let result = crate::owned_decode::from_json_slice(&bytes).map_err(|source| {
        match crate::owned_decode::current_budget().map(|budget| budget.failure()) {
            Some(Ok(Some(error))) | Some(Err(error)) => admission(error),
            Some(Ok(None)) | None => admission(DecodeAdmissionError::new(source)),
        }
    })?;
    check()?;
    Ok(result)
}

pub(in crate::trigger) fn check() -> Result<(), EngineError> {
    if let Some(budget) = crate::owned_decode::current_budget() {
        budget.check().map_err(admission)?;
    }
    Ok(())
}

impl HostAssertionEvaluator {
    /// Builds an evaluator after admitting its retained assertion definitions.
    ///
    /// # Errors
    /// Refuses unavailable or exhausted original metadata before copying a
    /// definition or allocating its shared owner.
    pub fn new(properties: &Properties) -> Result<Self, EngineError> {
        let budget = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = budget.enter();
        let (states, guest_marker_states) = partition_declared_assertions(properties)?;
        reserve_arc::<BTreeMap<NodeId, WhiteBoxPolicy>>()?;
        reserve_arc::<BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>>()?;
        reserve_arc::<BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>>()?;
        check()?;
        Ok(Self {
            states,
            guest_marker_states,
            once_latches: Vec::new(),
            white_box_policies: std::sync::Arc::new(BTreeMap::new()),
            code_points: std::sync::Arc::new(BTreeMap::new()),
            mem_places: std::sync::Arc::new(BTreeMap::new()),
            terminal_quiescence: None,
            last_position: None,
            _definition_custody: budget.custody(),
            _mutable_custody: Default::default(),
            evaluation_failure: None,
        })
    }

    /// Copies authoritative white-box policies under the evaluator's authority.
    ///
    /// # Errors
    /// Refuses the original metadata allowance before allocating table storage.
    pub fn with_white_box_policies(
        mut self,
        policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    ) -> Result<Self, EngineError> {
        let _scope = self._definition_custody.enter();
        reserve_arc::<BTreeMap<NodeId, WhiteBoxPolicy>>()?;
        let mut copied = BTreeMap::new();
        for (node, policy) in policies {
            crate::owned_decode::charge_btree_entry::<NodeId, WhiteBoxPolicy>()
                .map_err(admission)?;
            copied.insert(copy_node(node)?, *policy);
        }
        self.white_box_policies = std::sync::Arc::new(copied);
        check()?;
        Ok(self)
    }

    /// Copies white-box policies directly from borrowed world nodes.
    ///
    /// # Errors
    /// Refuses the original metadata allowance before copying node names or
    /// allocating a policy table entry.
    pub fn with_world_white_box_policies(mut self, world: &World) -> Result<Self, EngineError> {
        let _scope = self._definition_custody.enter();
        reserve_arc::<BTreeMap<NodeId, WhiteBoxPolicy>>()?;
        let mut policies = BTreeMap::new();
        for node in world.vm_nodes().iter() {
            crate::owned_decode::charge_btree_entry::<NodeId, WhiteBoxPolicy>()
                .map_err(admission)?;
            policies.insert(copy_node(&node.id)?, node.white_box);
        }
        self.white_box_policies = std::sync::Arc::new(policies);
        check()?;
        Ok(self)
    }

    /// Copies catalog-declared guest markers before event-log evaluation.
    ///
    /// # Errors
    /// Refuses the original metadata allowance before copying marker fields or
    /// growing the retained marker table.
    pub fn with_guest_assertion_catalog(
        mut self,
        catalog: &[GuestAssertionMarker],
    ) -> Result<Self, EngineError> {
        let _scope = self._definition_custody.enter();
        for marker in catalog {
            guest_marker_assertion_state_for(&mut self.guest_marker_states, marker)?;
        }
        check()?;
        Ok(self)
    }

    /// Copies borrowed host-side code-point resolutions.
    ///
    /// # Errors
    /// Refuses the original metadata allowance before copying owned table keys.
    pub fn with_resolved_code_points(
        mut self,
        code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    ) -> Result<Self, EngineError> {
        let _scope = self._definition_custody.enter();
        reserve_arc::<BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>>()?;
        let mut copied = BTreeMap::new();
        for (key, value) in code_points {
            crate::owned_decode::charge_btree_entry::<(NodeId, CodePoint), ResolvedCodePoint>()
                .map_err(admission)?;
            let point = match &key.1 {
                CodePoint::GuestAddress { address } => {
                    CodePoint::GuestAddress { address: *address }
                }
                CodePoint::Symbol { name } => CodePoint::Symbol {
                    name: copy_string(name)?,
                },
            };
            copied.insert((copy_node(&key.0)?, point), *value);
        }
        self.code_points = std::sync::Arc::new(copied);
        check()?;
        Ok(self)
    }

    /// Copies borrowed host-side memory-place resolutions.
    ///
    /// # Errors
    /// Refuses the original metadata allowance before copying table storage.
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    ) -> Result<Self, EngineError> {
        let _scope = self._definition_custody.enter();
        reserve_arc::<BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>>()?;
        let mut copied = BTreeMap::new();
        for (key, value) in mem_places {
            crate::owned_decode::charge_btree_entry::<(NodeId, MemPlace), ResolvedMemPlace>()
                .map_err(admission)?;
            let place = match &key.1 {
                MemPlace::PhysicalAddress { address, width } => MemPlace::PhysicalAddress {
                    address: *address,
                    width: *width,
                },
                MemPlace::VirtualAddress { address, width } => MemPlace::VirtualAddress {
                    address: *address,
                    width: *width,
                },
                MemPlace::Symbol { name, width } => MemPlace::Symbol {
                    name: copy_string(name)?,
                    width: *width,
                },
                MemPlace::Register { name, width } => MemPlace::Register {
                    name: copy_string(name)?,
                    width: *width,
                },
            };
            copied.insert((copy_node(&key.0)?, place), copy_json(value)?);
        }
        self.mem_places = std::sync::Arc::new(copied);
        check()?;
        Ok(self)
    }

    /// Copies borrowed terminal quiescence evidence.
    ///
    /// # Errors
    /// Refuses the original metadata allowance before copying owned blockers.
    pub fn with_terminal_scheduler_quiescence(
        mut self,
        quiescence: &SchedulerQuiescence,
    ) -> Result<Self, EngineError> {
        let _scope = self._definition_custody.enter();
        reserve_arc::<SchedulerQuiescence>()?;
        self.terminal_quiescence = Some(std::sync::Arc::new(copy_json(quiescence)?));
        check()?;
        Ok(self)
    }
}

/// Stable sorting holds one separately admitted temporary element bank.
pub(in crate::trigger) fn sort<T>(
    values: &mut [T],
    compare: impl FnMut(&T, &T) -> std::cmp::Ordering,
) -> Result<(), EngineError> {
    let _scratch = crate::owned_decode::current_budget()
        .map(|budget| budget.reserve_scratch_array::<T>(values.len()))
        .transpose()
        .map_err(admission)?;
    values.sort_by(compare);
    Ok(())
}

#[derive(Debug)]
struct AllocationSizeOverflow;

impl std::fmt::Display for AllocationSizeOverflow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("assertion allocation size overflow")
    }
}

impl std::error::Error for AllocationSizeOverflow {}

#[cfg(test)]
mod tests;
