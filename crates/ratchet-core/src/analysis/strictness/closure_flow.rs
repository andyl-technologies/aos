//! Bounded module-local closure-flow inference.
//!
//! The solver is a small 0CFA over lambda definition sites. It models forced
//! results rather than allocation identity: thunk wrappers are transparent,
//! lexical variables read static frame-slot variables, and calls connect a
//! simple lambda's argument slot and body result when its definition site
//! reaches the callee expression.

use std::collections::VecDeque;

use crate::FrameId;
use crate::ir::{Ir, IrAttrPathSegment, IrData, IrId, IrKind};

use super::{CallTargetCandidates, ClosureFlowReport, StrictnessAnalysisError, for_each_child};

const TARGET_CAP: usize = 8;

#[derive(Clone, Copy)]
struct FlowScope {
    frame: FrameId,
}

#[derive(Clone, Copy)]
struct CallSite {
    apply: IrId,
    function_var: usize,
    argument_var: usize,
    result_var: usize,
}

#[derive(Clone, Debug, Default)]
struct TargetSet {
    lambdas: Vec<IrId>,
    overflow: bool,
}

impl TargetSet {
    fn insert(&mut self, lambda: IrId) -> bool {
        if self.lambdas.contains(&lambda) {
            return false;
        }
        if self.lambdas.len() == TARGET_CAP {
            if self.overflow {
                return false;
            }
            self.overflow = true;
            return true;
        }
        self.lambdas.push(lambda);
        true
    }

    fn merge(&mut self, source: &Self) -> bool {
        let mut changed = false;
        for lambda in &source.lambdas {
            changed |= self.insert(*lambda);
        }
        if source.overflow && !self.overflow {
            self.overflow = true;
            changed = true;
        }
        changed
    }
}

pub(super) fn analyze(ir: &Ir) -> Result<ClosureFlowReport, StrictnessAnalysisError> {
    FlowAnalyzer::new(ir)?.run()
}

struct FlowAnalyzer<'a> {
    ir: &'a Ir,
    frame_offsets: Vec<usize>,
    values: Vec<TargetSet>,
    edges: Vec<Vec<usize>>,
    watchers: Vec<Vec<usize>>,
    calls: Vec<CallSite>,
    activated: Vec<Vec<IrId>>,
    seeds: Vec<(usize, IrId)>,
    inclusion_edges: usize,
    activated_call_edges: usize,
}

impl<'a> FlowAnalyzer<'a> {
    fn new(ir: &'a Ir) -> Result<Self, StrictnessAnalysisError> {
        let node_count = ir.arena.nodes().len();
        let mut frame_offsets = Vec::with_capacity(ir.frames.len());
        let mut variable_count = node_count;
        for frame in &*ir.frames {
            frame_offsets.push(variable_count);
            variable_count = variable_count
                .checked_add(frame.slot_count as usize)
                .ok_or(StrictnessAnalysisError::InvalidFactTableLength {
                    expected: usize::MAX,
                    actual: node_count,
                })?;
        }
        Ok(Self {
            ir,
            frame_offsets,
            values: vec![TargetSet::default(); variable_count],
            edges: vec![Vec::new(); variable_count],
            watchers: vec![Vec::new(); variable_count],
            calls: Vec::new(),
            activated: Vec::new(),
            seeds: Vec::new(),
            inclusion_edges: 0,
            activated_call_edges: 0,
        })
    }

    fn run(mut self) -> Result<ClosureFlowReport, StrictnessAnalysisError> {
        self.build(self.ir.root, &mut Vec::new())?;
        self.activated.resize(self.calls.len(), Vec::new());
        for (index, call) in self.calls.iter().enumerate() {
            self.watchers[call.function_var].push(index);
        }

        let mut queue = VecDeque::new();
        let mut queued = vec![false; self.values.len()];
        for (variable, lambda) in std::mem::take(&mut self.seeds) {
            if self.values[variable].insert(lambda) {
                enqueue(variable, &mut queue, &mut queued);
            }
        }
        let mut worklist_pops = 0;
        while let Some(source) = queue.pop_front() {
            queued[source] = false;
            worklist_pops += 1;
            let source_value = self.values[source].clone();
            let destinations = self.edges[source].clone();
            for destination in destinations {
                if self.values[destination].merge(&source_value) {
                    enqueue(destination, &mut queue, &mut queued);
                }
            }
            let watchers = self.watchers[source].clone();
            for call_index in watchers {
                self.activate_call_targets(call_index, &mut queue, &mut queued)?;
            }
        }

        let calls = self
            .calls
            .iter()
            .map(|call| {
                let value = &self.values[call.function_var];
                CallTargetCandidates {
                    apply: call.apply,
                    lambdas: value.lambdas.clone().into_boxed_slice(),
                    overflow: value.overflow,
                }
            })
            .collect();
        Ok(ClosureFlowReport {
            calls,
            inclusion_edges: self.inclusion_edges,
            activated_call_edges: self.activated_call_edges,
            worklist_pops,
        })
    }

    fn activate_call_targets(
        &mut self,
        call_index: usize,
        queue: &mut VecDeque<usize>,
        queued: &mut [bool],
    ) -> Result<(), StrictnessAnalysisError> {
        let call = self.calls[call_index];
        let targets = self.values[call.function_var].lambdas.clone();
        for lambda in targets {
            if self.activated[call_index].contains(&lambda) {
                continue;
            }
            self.activated[call_index].push(lambda);
            let node = *self
                .ir
                .arena
                .node(lambda)
                .ok_or(StrictnessAnalysisError::InvalidNode { id: lambda })?;
            let IrData::Lambda {
                pattern,
                body,
                frame: Some(frame),
            } = node.data
            else {
                continue;
            };
            let pattern_node = *self
                .ir
                .arena
                .node(pattern)
                .ok_or(StrictnessAnalysisError::InvalidNode { id: pattern })?;
            if pattern_node.kind != IrKind::Formal
                || !matches!(pattern_node.data, IrData::Formal { default: None, .. })
            {
                continue;
            }
            let frame_info = self
                .ir
                .frames
                .get(frame.index())
                .ok_or(StrictnessAnalysisError::InvalidFrame { id: lambda, frame })?;
            if frame_info.slot_count != 1 {
                continue;
            }
            let slot = self.slot_var(lambda, frame, 0)?;
            self.add_dynamic_edge(call.argument_var, slot, queue, queued);
            self.add_dynamic_edge(self.expr_var(body), call.result_var, queue, queued);
        }
        Ok(())
    }

    fn add_dynamic_edge(
        &mut self,
        source: usize,
        destination: usize,
        queue: &mut VecDeque<usize>,
        queued: &mut [bool],
    ) {
        if !self.add_edge(source, destination) {
            return;
        }
        self.activated_call_edges += 1;
        let source_value = self.values[source].clone();
        if self.values[destination].merge(&source_value) {
            enqueue(destination, queue, queued);
        }
    }

    fn build(
        &mut self,
        id: IrId,
        stack: &mut Vec<FlowScope>,
    ) -> Result<(), StrictnessAnalysisError> {
        let node = *self
            .ir
            .arena
            .node(id)
            .ok_or(StrictnessAnalysisError::InvalidNode { id })?;
        match node.data {
            IrData::Lambda {
                pattern,
                body,
                frame,
            } => {
                self.seeds.push((self.expr_var(id), id));
                if let Some(frame) = frame {
                    self.check_frame(id, frame)?;
                    stack.push(FlowScope { frame });
                    self.build(pattern, stack)?;
                    let result = self.build(body, stack);
                    stack.pop();
                    result
                } else {
                    self.build(pattern, stack)?;
                    self.build(body, stack)
                }
            }
            IrData::Let {
                bindings,
                body,
                frame,
            } => {
                let entries = self.bindings(id, bindings)?.to_vec();
                if let Some(frame) = frame {
                    self.check_frame(id, frame)?;
                    stack.push(FlowScope { frame });
                    for (slot, binding) in entries.iter().enumerate() {
                        let slot = self.slot_var(id, frame, slot as u32)?;
                        self.add_edge(self.expr_var(binding.value), slot);
                        if let IrAttrPathSegment::Dynamic(key) = binding.key {
                            self.build(key, stack)?;
                        }
                        self.build(binding.value, stack)?;
                    }
                    self.add_edge(self.expr_var(body), self.expr_var(id));
                    let result = self.build(body, stack);
                    stack.pop();
                    result
                } else {
                    for binding in entries {
                        if let IrAttrPathSegment::Dynamic(key) = binding.key {
                            self.build(key, stack)?;
                        }
                        self.build(binding.value, stack)?;
                    }
                    self.add_edge(self.expr_var(body), self.expr_var(id));
                    self.build(body, stack)
                }
            }
            IrData::AttrSet {
                bindings,
                recursive: true,
                frame,
                ..
            } => {
                let entries = self.bindings(id, bindings)?.to_vec();
                if let Some(frame) = frame {
                    self.check_frame(id, frame)?;
                    stack.push(FlowScope { frame });
                    let mut slot = 0_u32;
                    for binding in entries {
                        if matches!(binding.key, IrAttrPathSegment::Static(_)) {
                            let destination = self.slot_var(id, frame, slot)?;
                            self.add_edge(self.expr_var(binding.value), destination);
                            slot += 1;
                        }
                        if let IrAttrPathSegment::Dynamic(key) = binding.key {
                            self.build(key, stack)?;
                        }
                        self.build(binding.value, stack)?;
                    }
                    stack.pop();
                    Ok(())
                } else {
                    for binding in entries {
                        if let IrAttrPathSegment::Dynamic(key) = binding.key {
                            self.build(key, stack)?;
                        }
                        self.build(binding.value, stack)?;
                    }
                    Ok(())
                }
            }
            IrData::Local { slot } => {
                if let Some(scope) = stack.last().copied() {
                    let source = self.slot_var(id, scope.frame, slot)?;
                    self.add_edge(source, self.expr_var(id));
                }
                Ok(())
            }
            IrData::Upval { depth, slot } => {
                if let Some(index) = stack.len().checked_sub(1 + depth as usize) {
                    let source = self.slot_var(id, stack[index].frame, slot)?;
                    self.add_edge(source, self.expr_var(id));
                }
                Ok(())
            }
            IrData::Pair {
                first: function,
                second: argument,
            } if node.kind == IrKind::Apply => {
                self.calls.push(CallSite {
                    apply: id,
                    function_var: self.expr_var(function),
                    argument_var: self.expr_var(argument),
                    result_var: self.expr_var(id),
                });
                self.build(function, stack)?;
                self.build(argument, stack)
            }
            IrData::Node(body) if node.kind == IrKind::ThunkAlloc => {
                self.add_edge(self.expr_var(body), self.expr_var(id));
                self.build(body, stack)
            }
            IrData::Triple {
                first: condition,
                second: then_branch,
                third: else_branch,
            } if node.kind == IrKind::If => {
                self.add_edge(self.expr_var(then_branch), self.expr_var(id));
                self.add_edge(self.expr_var(else_branch), self.expr_var(id));
                self.build(condition, stack)?;
                self.build(then_branch, stack)?;
                self.build(else_branch, stack)
            }
            IrData::Pair {
                first,
                second: body,
            } if matches!(node.kind, IrKind::With | IrKind::Assert) => {
                self.add_edge(self.expr_var(body), self.expr_var(id));
                self.build(first, stack)?;
                self.build(body, stack)
            }
            _ => {
                let mut children = Vec::new();
                for_each_child(self.ir, id, node, &mut |child| {
                    children.push(child);
                    Ok(())
                })?;
                for child in children {
                    self.build(child, stack)?;
                }
                Ok(())
            }
        }
    }

    fn expr_var(&self, id: IrId) -> usize {
        id.index()
    }

    fn slot_var(
        &self,
        id: IrId,
        frame: FrameId,
        slot: u32,
    ) -> Result<usize, StrictnessAnalysisError> {
        let frame_info = self
            .ir
            .frames
            .get(frame.index())
            .ok_or(StrictnessAnalysisError::InvalidFrame { id, frame })?;
        if slot >= frame_info.slot_count {
            return Err(StrictnessAnalysisError::InvalidFrame { id, frame });
        }
        Ok(self.frame_offsets[frame.index()] + slot as usize)
    }

    fn check_frame(&self, id: IrId, frame: FrameId) -> Result<(), StrictnessAnalysisError> {
        self.ir
            .frames
            .get(frame.index())
            .map(|_| ())
            .ok_or(StrictnessAnalysisError::InvalidFrame { id, frame })
    }

    fn bindings(
        &self,
        id: IrId,
        slice: crate::ir::IrBindingSlice,
    ) -> Result<&[crate::ir::IrBinding], StrictnessAnalysisError> {
        let start = slice.start as usize;
        let end = start
            .checked_add(slice.len())
            .ok_or(StrictnessAnalysisError::InvalidBindingSlice { id, slice })?;
        self.ir
            .bindings
            .get(start..end)
            .ok_or(StrictnessAnalysisError::InvalidBindingSlice { id, slice })
    }

    fn add_edge(&mut self, source: usize, destination: usize) -> bool {
        if self.edges[source].contains(&destination) {
            return false;
        }
        self.edges[source].push(destination);
        self.inclusion_edges += 1;
        true
    }
}

fn enqueue(variable: usize, queue: &mut VecDeque<usize>, queued: &mut [bool]) {
    if !queued[variable] {
        queued[variable] = true;
        queue.push_back(variable);
    }
}
