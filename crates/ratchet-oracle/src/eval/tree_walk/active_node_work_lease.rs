//! Evaluator-owned work detached from active ordinary Node blackholes.

use std::ptr::NonNull;

use crate::value::HeapObject;

use super::*;

/// Authoritative Node work while its source payload is an edge-free blackhole.
#[derive(Debug)]
pub(super) struct ActiveNodeWorkLease {
    pub(super) token: ForceLeaseToken,
    pub(super) source: Value,
    pub(super) ptr: NonNull<HeapObject>,
    pub(super) work: EvalThunk,
}

impl TreeWalk {
    fn active_node_work_lease_index(&self, depth: usize) -> Option<usize> {
        self.active_node_work_leases
            .len()
            .checked_sub(depth.checked_add(1)?)
    }

    pub(super) fn active_node_work_root_value(
        &self,
        depth: usize,
        edge: usize,
    ) -> Result<Option<Value>, EvalHeapError> {
        let Some(index) = self.active_node_work_lease_index(depth) else {
            return Ok(None);
        };
        let Some(lease) = self.active_node_work_leases.get(index) else {
            return Ok(None);
        };
        self.heap
            .detached_node_thunk_work_edge(lease.ptr, &lease.work, edge)
            .map(|edge| Some(edge.value()))
    }

    pub(super) fn rewrite_active_node_work_root(
        &mut self,
        depth: usize,
        edge: usize,
        replacement: Value,
    ) -> Result<bool, EvalHeapError> {
        let Some(index) = self.active_node_work_lease_index(depth) else {
            return Ok(false);
        };
        let (heap, leases) = (&mut self.heap, &mut self.active_node_work_leases);
        let Some(lease) = leases.get_mut(index) else {
            return Ok(false);
        };
        heap.rewrite_detached_node_thunk_work_edge(lease.ptr, &mut lease.work, edge, replacement)?;
        Ok(true)
    }

    pub(super) fn active_node_work_for_token(&self, token: ForceLeaseToken) -> Option<&EvalThunk> {
        self.active_node_work_leases
            .last()
            .filter(|lease| lease.token == token)
            .map(|lease| &lease.work)
    }

    pub(super) fn pop_active_node_work_lease(
        &mut self,
        token: ForceLeaseToken,
    ) -> Option<ActiveNodeWorkLease> {
        if self
            .active_node_work_leases
            .last()
            .is_some_and(|lease| lease.token == token)
        {
            self.active_node_work_leases.pop()
        } else {
            None
        }
    }
}
