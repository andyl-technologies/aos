//! Per-frame reachability proof for lazy `let` binding thunks (S9).
//!
//! A binding thunk stays frame-local when every reference to its slot,
//! anywhere in the frame's subtree, sits in a position the frame's own
//! execution forces in place — so the handle is consumed while the frame
//! runs and nothing can retain it:
//!
//! - **primop clause** — the reference is an argument the per-argument escape
//!   signature table proves consumed
//!   ([`PrimOpArgumentEscape::Consumed`]): forced at most once,
//!   never retained in or returned as part of the result.
//! - **operator clauses** — `if`/`assert` conditions, unary/binary operator
//!   operands, and `select`/`hasAttr` receivers force the handle immediately
//!   and build fresh results.
//!
//! Everything else declines. In particular the **result clause fails
//! closed**: a reference whose value flows along result edges (frame body
//! result, `if` branch results, `select` defaults) escapes, because the
//! frame's result can itself be the deferred body of an enclosing update
//! thunk — that thunk caches the raw handle and every re-read of its cache
//! re-forces the handle, which a single-entry (uncached) representation
//! would re-evaluate. Likewise **capture** (any reference inside a lambda
//! body or another thunk's body — the closure retains the handle beyond the
//! frame's execution, S7), **containers** (list elements, attrset values),
//! **unknown calls** (application arguments, and callees, whose `__functor`
//! protocol can pass the callee itself onward), **interning** (dynamic
//! attribute keys, string interpolation with its `__toString` protocol), and
//! dialect operations all decline.
//!
//! The scan runs once per `let` frame and classifies references to *all* of
//! the frame's slots simultaneously, and direct node reference counts are
//! precomputed in one arena pass — the pass is linear in the module modulo
//! `let` nesting depth, never per-binding quadratic.

use crate::analysis::PrimOpArgumentEscape;
use crate::analysis::escape_signature::primop_argument_escape_signature;
use crate::ir::{Ir, IrAttrPathId, IrAttrPathSegment, IrBindingSlice, IrData, IrId, IrKind};

use super::{EscapeAnalysisError, binding_values, child_ids, expected_payload, validate_node};

/// Returns every `let` binding thunk allocation proven frame-local.
///
/// # Errors
///
/// Returns [`EscapeAnalysisError`] when the arena, side tables, or node
/// payloads are internally inconsistent.
pub(super) fn frame_local_let_thunks(ir: &Ir) -> Result<Vec<IrId>, EscapeAnalysisError> {
    let reference_counts = direct_reference_counts(ir)?;
    let mut thunks = Vec::new();
    for (index, node) in ir.arena.nodes().iter().copied().enumerate() {
        if node.kind != IrKind::Let {
            continue;
        }
        let let_node = IrId::new(index as u32);
        let IrData::Let { bindings, body, .. } = node.data else {
            return Err(EscapeAnalysisError::InvalidPayload {
                id: let_node,
                kind: node.kind,
                expected: expected_payload(node.kind),
            });
        };
        validate_node(ir, body)?;
        let bindings = binding_values(ir, let_node, bindings)?;
        if bindings
            .iter()
            .any(|binding| matches!(binding.key, IrAttrPathSegment::Dynamic(_)))
        {
            continue;
        }
        // One scan classifies references to every slot of this frame.
        let mut scan = FrameEscapeScan::new(ir, bindings.len());
        scan.visit(body, 0, Position::root())?;
        for sibling in bindings.iter().copied() {
            // Binding values are thunk allocations; their bodies scan under
            // the capture barrier, so a self-reference or a sibling capture
            // of a slot declines that slot's proof.
            scan.visit(sibling.value, 0, Position::root())?;
        }
        for (slot, binding) in bindings.iter().copied().enumerate() {
            if scan.escaped(slot) {
                continue;
            }
            let value_node = *ir
                .arena
                .node(binding.value)
                .ok_or(EscapeAnalysisError::InvalidNode { id: binding.value })?;
            let (IrKind::ThunkAlloc, IrData::Node(thunk_body)) =
                (value_node.kind, value_node.data)
            else {
                continue;
            };
            validate_node(ir, thunk_body)?;
            if thunk_body == binding.value {
                continue;
            }
            if reference_counts
                .get(binding.value.index())
                .copied()
                .unwrap_or(u32::MAX)
                != 1
            {
                continue;
            }
            thunks.push(binding.value);
        }
    }
    Ok(thunks)
}

/// Counts direct IR references to every node in one arena pass.
///
/// This is the whole-table analogue of the per-target
/// [`super::direct_reference_count`]: the module root, every `with`-chain
/// scope, and every node-payload child edge each contribute one reference to
/// the referenced id.
fn direct_reference_counts(ir: &Ir) -> Result<Vec<u32>, EscapeAnalysisError> {
    let mut counts = vec![0u32; ir.arena.nodes().len()];
    fn bump(counts: &mut [u32], id: IrId) {
        if let Some(count) = counts.get_mut(id.index()) {
            *count = count.saturating_add(1);
        }
    }
    bump(&mut counts, ir.root);
    for chain in ir.with_chains.iter() {
        for scope in chain.scopes.iter().copied() {
            validate_node(ir, scope)?;
            bump(&mut counts, scope);
        }
    }
    for (index, node) in ir.arena.nodes().iter().copied().enumerate() {
        let id = IrId::new(index as u32);
        match node.data {
            IrData::None
            | IrData::Int(_)
            | IrData::Float(_)
            | IrData::Bool(_)
            | IrData::Symbol(_)
            | IrData::GlobalVar { .. }
            | IrData::Local { .. }
            | IrData::Upval { .. }
            | IrData::DialectScopeVar { .. } => {}
            IrData::SearchPath { search_path, .. } => {
                if let Some(search_path) = search_path {
                    bump(&mut counts, search_path);
                }
            }
            IrData::Node(child) | IrData::Unary { operand: child, .. } => {
                bump(&mut counts, child);
            }
            IrData::Pair { first, second }
            | IrData::Binary {
                lhs: first,
                rhs: second,
                ..
            } => {
                bump(&mut counts, first);
                bump(&mut counts, second);
            }
            IrData::Triple {
                first,
                second,
                third,
            } => {
                bump(&mut counts, first);
                bump(&mut counts, second);
                bump(&mut counts, third);
            }
            IrData::Children(slice) | IrData::PrimOp { args: slice, .. } => {
                for child in child_ids(ir, id, slice)? {
                    bump(&mut counts, *child);
                }
            }
            IrData::Bindings(slice)
            | IrData::AttrSet {
                bindings: slice, ..
            } => {
                for binding in binding_values(ir, id, slice)? {
                    if let IrAttrPathSegment::Dynamic(key) = binding.key {
                        validate_node(ir, key)?;
                        bump(&mut counts, key);
                    }
                    validate_node(ir, binding.value)?;
                    bump(&mut counts, binding.value);
                }
            }
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                bump(&mut counts, receiver);
                if let Some(default) = default {
                    bump(&mut counts, default);
                }
                for segment in attr_path_segments(ir, id, path)? {
                    if let IrAttrPathSegment::Dynamic(dynamic) = segment {
                        validate_node(ir, *dynamic)?;
                        bump(&mut counts, *dynamic);
                    }
                }
            }
            IrData::HasAttr { receiver, path, .. } => {
                bump(&mut counts, receiver);
                for segment in attr_path_segments(ir, id, path)? {
                    if let IrAttrPathSegment::Dynamic(dynamic) = segment {
                        validate_node(ir, *dynamic)?;
                        bump(&mut counts, *dynamic);
                    }
                }
            }
            IrData::DialectNode { argument, .. } => bump(&mut counts, argument),
            IrData::Lambda { pattern, body, .. } => {
                bump(&mut counts, pattern);
                bump(&mut counts, body);
            }
            IrData::Let { bindings, body, .. } => {
                for binding in binding_values(ir, id, bindings)? {
                    if let IrAttrPathSegment::Dynamic(key) = binding.key {
                        validate_node(ir, key)?;
                        bump(&mut counts, key);
                    }
                    validate_node(ir, binding.value)?;
                    bump(&mut counts, binding.value);
                }
                bump(&mut counts, body);
            }
            IrData::FormalSet { formals, .. } => {
                for formal in child_ids(ir, id, formals)? {
                    bump(&mut counts, *formal);
                }
            }
            IrData::Formal { default, .. } => {
                if let Some(default) = default {
                    bump(&mut counts, default);
                }
            }
        }
    }
    Ok(counts)
}

fn attr_path_segments<'a>(
    ir: &'a Ir,
    id: IrId,
    path: IrAttrPathId,
) -> Result<&'a [IrAttrPathSegment], EscapeAnalysisError> {
    ir.attr_paths
        .get(path.index())
        .map(Box::as_ref)
        .ok_or(EscapeAnalysisError::InvalidAttrPath { id, path })
}

/// The value-flow context of one scanned expression position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Position {
    /// The position's value may be retained beyond the frame's execution
    /// (result flow, container element, call argument, interning boundary,
    /// ...). A target reference here escapes.
    retained: bool,
    /// The position sits inside a closure body (lambda or another thunk),
    /// whose captured environment holds the frame handle beyond the frame's
    /// own execution (S7). Any target reference here escapes.
    captured: bool,
}

impl Position {
    /// A scan root: result flow is retained until a forcing position clears
    /// it (see the module docs on why the result clause fails closed).
    const fn root() -> Self {
        Self {
            retained: true,
            captured: false,
        }
    }

    /// Returns this position with the retained bit set.
    const fn retain(self) -> Self {
        Self {
            retained: true,
            captured: self.captured,
        }
    }

    /// Returns this position with the retained bit cleared (forced in place).
    const fn consume(self) -> Self {
        Self {
            retained: false,
            captured: self.captured,
        }
    }

    /// Returns this position inside a closure capture.
    const fn capture(self) -> Self {
        Self {
            retained: self.retained,
            captured: true,
        }
    }

    const fn escapes(self) -> bool {
        self.retained || self.captured
    }
}

/// Scans one frame subtree, classifying references to every frame slot.
struct FrameEscapeScan<'a> {
    ir: &'a Ir,
    escaped: Vec<bool>,
}

impl<'a> FrameEscapeScan<'a> {
    fn new(ir: &'a Ir, slots: usize) -> Self {
        Self {
            ir,
            escaped: vec![false; slots],
        }
    }

    fn escaped(&self, slot: usize) -> bool {
        self.escaped.get(slot).copied().unwrap_or(true)
    }

    fn record(&mut self, slot: u32, position: Position) {
        if !position.escapes() {
            return;
        }
        if let Some(flag) = self.escaped.get_mut(slot as usize) {
            *flag = true;
        }
    }

    /// Visits `id` at `depth` frames below the analyzed frame.
    ///
    /// References to the analyzed frame's slots appear as `Local` at depth 0
    /// and as `Upval` whose depth field equals `depth` otherwise.
    fn visit(
        &mut self,
        id: IrId,
        depth: u32,
        position: Position,
    ) -> Result<(), EscapeAnalysisError> {
        let node = *self
            .ir
            .arena
            .node(id)
            .ok_or(EscapeAnalysisError::InvalidNode { id })?;
        match node.data {
            IrData::None
            | IrData::Int(_)
            | IrData::Float(_)
            | IrData::Bool(_)
            | IrData::Symbol(_)
            | IrData::GlobalVar { .. }
            | IrData::DialectScopeVar { .. } => {}
            IrData::Local { slot } => {
                if depth == 0 {
                    self.record(slot, position);
                }
            }
            IrData::Upval {
                depth: upval_depth,
                slot,
            } => {
                if upval_depth == depth {
                    self.record(slot, position);
                }
            }
            IrData::SearchPath { search_path, .. } => {
                if let Some(search_path) = search_path {
                    self.visit(search_path, depth, position.retain())?;
                }
            }
            IrData::Node(child) => {
                if node.kind == IrKind::ThunkAlloc {
                    // Another thunk's captured environment holds the frame
                    // handle beyond this execution.
                    self.visit(child, depth, position.capture())?;
                } else if node.kind == IrKind::Interp {
                    // String coercion can route through a `__toString`
                    // functor that receives the value itself.
                    self.visit(child, depth, position.retain())?;
                } else {
                    self.visit(child, depth, position)?;
                }
            }
            IrData::Pair { first, second } => match node.kind {
                IrKind::Apply => {
                    // The callee's `__functor` protocol can pass the callee
                    // itself onward; the argument is stored in the callee's
                    // frame, which can outlive this one.
                    self.visit(first, depth, position.retain())?;
                    self.visit(second, depth, position.retain())?;
                }
                IrKind::With => {
                    // The scrutinee is retained in the dynamic scope, which
                    // body-allocated closures capture.
                    self.visit(first, depth, position.retain())?;
                    self.visit(second, depth, position)?;
                }
                IrKind::Assert => {
                    self.visit(first, depth, position.consume())?;
                    self.visit(second, depth, position)?;
                }
                _ => {
                    self.visit(first, depth, position.retain())?;
                    self.visit(second, depth, position.retain())?;
                }
            },
            IrData::Triple {
                first,
                second,
                third,
            } => {
                // `if`: the condition is forced in place; branch results flow
                // to the conditional's own position.
                self.visit(first, depth, position.consume())?;
                self.visit(second, depth, position)?;
                self.visit(third, depth, position)?;
            }
            IrData::Children(slice) => {
                // List literals retain their elements.
                for child in child_ids(self.ir, id, slice)?.to_vec() {
                    self.visit(child, depth, position.retain())?;
                }
            }
            IrData::PrimOp { args, .. } => {
                self.visit_primop(id, node.data, args, depth, position)?;
            }
            IrData::Bindings(slice) => {
                self.visit_bindings(id, slice, depth, position.retain())?;
            }
            IrData::Binary { lhs, rhs, .. } => {
                // Every binary operator forces its operands and builds a
                // fresh result; member sharing (`//`, `++`) retains operand
                // members, never the operand handle itself.
                self.visit(lhs, depth, position.consume())?;
                self.visit(rhs, depth, position.consume())?;
            }
            IrData::Unary { operand, .. } => {
                self.visit(operand, depth, position.consume())?;
            }
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                self.visit(receiver, depth, position.consume())?;
                if let Some(default) = default {
                    self.visit(default, depth, position)?;
                }
                self.visit_attr_path(id, path, depth, position)?;
            }
            IrData::HasAttr { receiver, path, .. } => {
                self.visit(receiver, depth, position.consume())?;
                self.visit_attr_path(id, path, depth, position)?;
            }
            IrData::DialectNode { argument, .. } => {
                self.visit(argument, depth, position.retain())?;
            }
            IrData::Lambda { pattern, body, .. } => {
                // The closure captures the frame chain; its body may run
                // after the frame's execution completes (or concurrently).
                self.visit(pattern, depth + 1, position.capture())?;
                self.visit(body, depth + 1, position.capture())?;
            }
            IrData::Let { bindings, body, .. } => {
                self.visit_bindings(id, bindings, depth + 1, position)?;
                self.visit(body, depth + 1, position)?;
            }
            IrData::AttrSet {
                bindings,
                recursive,
                ..
            } => {
                let binding_depth = if recursive { depth + 1 } else { depth };
                self.visit_bindings(id, bindings, binding_depth, position.retain())?;
            }
            IrData::FormalSet { formals, .. } => {
                for formal in child_ids(self.ir, id, formals)?.to_vec() {
                    self.visit(formal, depth, position)?;
                }
            }
            IrData::Formal { default, .. } => {
                if let Some(default) = default {
                    self.visit(default, depth, position)?;
                }
            }
        }
        Ok(())
    }

    fn visit_primop(
        &mut self,
        id: IrId,
        data: IrData,
        args: crate::ir::IrChildSlice,
        depth: u32,
        position: Position,
    ) -> Result<(), EscapeAnalysisError> {
        let signature = primop_argument_signature(self.ir, id, data)?;
        let children = child_ids(self.ir, id, args)?.to_vec();
        for (index, child) in children.into_iter().enumerate() {
            let argument_position = match signature {
                Some(signature) => match signature.get(index) {
                    Some(PrimOpArgumentEscape::Consumed) => position.consume(),
                    Some(PrimOpArgumentEscape::Retained) | None => position.retain(),
                },
                None => position.retain(),
            };
            self.visit(child, depth, argument_position)?;
        }
        Ok(())
    }

    fn visit_bindings(
        &mut self,
        id: IrId,
        slice: IrBindingSlice,
        depth: u32,
        position: Position,
    ) -> Result<(), EscapeAnalysisError> {
        for binding in binding_values(self.ir, id, slice)?.to_vec() {
            if let IrAttrPathSegment::Dynamic(key) = binding.key {
                // Dynamic keys are forced and interned.
                self.visit(key, depth, position.retain())?;
            }
            self.visit(binding.value, depth, position)?;
        }
        Ok(())
    }

    fn visit_attr_path(
        &mut self,
        id: IrId,
        path: IrAttrPathId,
        depth: u32,
        position: Position,
    ) -> Result<(), EscapeAnalysisError> {
        let segments = self
            .ir
            .attr_paths
            .get(path.index())
            .ok_or(EscapeAnalysisError::InvalidAttrPath { id, path })?
            .to_vec();
        for segment in segments {
            if let IrAttrPathSegment::Dynamic(dynamic) = segment {
                // Dynamic path keys are forced and interned.
                self.visit(dynamic, depth, position.retain())?;
            }
        }
        Ok(())
    }
}

/// Resolves the enabled per-argument escape signature for a primop node.
///
/// Validates direct-primop arity exactly like the result-signature path, so
/// malformed nodes reject instead of silently classifying.
fn primop_argument_signature(
    ir: &Ir,
    id: IrId,
    data: IrData,
) -> Result<Option<&'static [PrimOpArgumentEscape]>, EscapeAnalysisError> {
    let IrData::PrimOp { symbol, .. } = data else {
        return Ok(None);
    };
    // Reuse the result-signature resolver for symbol/arity validation.
    super::primop_signature(ir, id, data)?;
    let name = ir
        .symbols
        .resolve(symbol)
        .ok_or(EscapeAnalysisError::InvalidSymbol { id, symbol })?;
    Ok(primop_argument_escape_signature(name))
}
