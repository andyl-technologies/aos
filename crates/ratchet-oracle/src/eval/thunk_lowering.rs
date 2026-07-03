//! Tree-walk thunk allocation planning.
//!
//! Phase 3.5 needs a single boundary where analysis facts are consumed before a
//! thunk allocation site is allowed to skip update and blackhole state. This
//! module preserves the existing strictness-lowering and order-sensitive
//! binding rules while naming the lazy-storage decision that later runtime
//! representations will implement.

use thiserror::Error;

use crate::compile::{
    BindingLowering, FrameLocalSingleEntryThunk, FrameLocalThunkDowngrade,
    FrameLocalThunkDowngradeError, FrameLocalThunkUpdateReason, Ir, IrData, IrId, IrKind,
    frame_local_single_entry_thunk_downgrade,
};

/// Builds the tree-walk allocation plan for one lowered thunk allocation.
///
/// Strict facts may elide the thunk entirely by evaluating the body to WHNF.
/// When the thunk remains lazy, a single-entry plan is returned only if the
/// C-8 frame-local predicate admits it. Order-sensitive binding assembly keeps a
/// normal update slot regardless of facts so frame population cannot observe
/// reordered evaluation.
///
/// # Errors
///
/// Returns [`TreeWalkThunkAllocationError`] if `id` does not identify a
/// well-formed [`IrKind::ThunkAlloc`] node, or if demand-position planning
/// requires an analysis fact record that is missing.
pub fn tree_walk_thunk_allocation_plan(
    ir: &Ir,
    id: IrId,
    context: TreeWalkThunkAllocationContext,
) -> Result<TreeWalkThunkAllocationPlan, TreeWalkThunkAllocationError> {
    let body = thunk_alloc_body(ir, id)?;
    if context == TreeWalkThunkAllocationContext::OrderSensitiveBindingAssembly {
        return Ok(TreeWalkThunkAllocationPlan::UpdateSlot(
            TreeWalkThunkUpdateSlot::new(
                id,
                body,
                TreeWalkThunkUpdateReason::OrderSensitiveBindingAssembly,
            ),
        ));
    }

    let downgrade = frame_local_single_entry_thunk_downgrade(ir, id)?;
    if let FrameLocalThunkDowngrade::KeepUpdate(FrameLocalThunkUpdateReason::AbsentButStrict) =
        downgrade
    {
        return Ok(TreeWalkThunkAllocationPlan::UpdateSlot(
            TreeWalkThunkUpdateSlot::new(
                id,
                body,
                TreeWalkThunkUpdateReason::SharingProof(
                    FrameLocalThunkUpdateReason::AbsentButStrict,
                ),
            ),
        ));
    }

    let lowering = ir
        .node_facts(id)
        .ok_or(FrameLocalThunkDowngradeError::MissingFact { id })?
        .binding_lowering();
    if matches!(lowering, BindingLowering::Eager | BindingLowering::Scalar) {
        return Ok(TreeWalkThunkAllocationPlan::ElideToWhnf(
            TreeWalkThunkElision::new(id, body, lowering),
        ));
    }

    Ok(match downgrade {
        FrameLocalThunkDowngrade::KeepUpdate(reason) => TreeWalkThunkAllocationPlan::UpdateSlot(
            TreeWalkThunkUpdateSlot::new(id, body, TreeWalkThunkUpdateReason::SharingProof(reason)),
        ),
        FrameLocalThunkDowngrade::SingleEntry(single_entry) => {
            TreeWalkThunkAllocationPlan::SingleEntry(single_entry)
        }
        FrameLocalThunkDowngrade::Omit => {
            TreeWalkThunkAllocationPlan::Omit(TreeWalkOmittedThunk::new(id, body))
        }
    })
}

fn thunk_alloc_body(ir: &Ir, id: IrId) -> Result<IrId, TreeWalkThunkAllocationError> {
    let node = ir
        .arena
        .node(id)
        .ok_or(FrameLocalThunkDowngradeError::MissingNode { id })?;
    let body = match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => body,
        (IrKind::ThunkAlloc, _) => {
            return Err(FrameLocalThunkDowngradeError::InvalidPayload {
                id,
                expected: "thunk body",
            }
            .into());
        }
        (kind, _) => return Err(FrameLocalThunkDowngradeError::NotThunkAlloc { id, kind }.into()),
    };
    ir.arena
        .node(body)
        .ok_or(FrameLocalThunkDowngradeError::MissingThunkBody { id, body })?;
    Ok(body)
}

/// The evaluator context in which a thunk allocation appears.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TreeWalkThunkAllocationContext {
    /// The thunk appears in a normal demand/lazy allocation position.
    #[default]
    DemandPosition,
    /// The thunk appears while a `let`, attrset, or formal frame is populated.
    OrderSensitiveBindingAssembly,
}

/// The action selected for one lowered thunk allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeWalkThunkAllocationPlan {
    /// Allocate ordinary update and blackhole state.
    UpdateSlot(TreeWalkThunkUpdateSlot),
    /// Allocate the future single-entry representation for a frame-local thunk.
    SingleEntry(FrameLocalSingleEntryThunk),
    /// Omit storage for a proven-absent lazy binding.
    Omit(TreeWalkOmittedThunk),
    /// Evaluate the thunk body directly to WHNF instead of allocating storage.
    ElideToWhnf(TreeWalkThunkElision),
}

/// An ordinary memoizing thunk allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeWalkThunkUpdateSlot {
    thunk: IrId,
    body: IrId,
    reason: TreeWalkThunkUpdateReason,
}

impl TreeWalkThunkUpdateSlot {
    const fn new(thunk: IrId, body: IrId, reason: TreeWalkThunkUpdateReason) -> Self {
        Self {
            thunk,
            body,
            reason,
        }
    }

    /// Returns the thunk allocation node.
    pub const fn thunk(self) -> IrId {
        self.thunk
    }

    /// Returns the deferred thunk body.
    pub const fn body(self) -> IrId {
        self.body
    }

    /// Returns why ordinary update and blackhole state is required.
    pub const fn reason(self) -> TreeWalkThunkUpdateReason {
        self.reason
    }
}

/// Why the planner kept ordinary update and blackhole state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeWalkThunkUpdateReason {
    /// Frame population is order-sensitive, so lazy storage must be retained.
    OrderSensitiveBindingAssembly,
    /// The C-8 sharing proof did not admit single-entry storage.
    SharingProof(FrameLocalThunkUpdateReason),
}

/// A proven-absent thunk allocation with no required storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeWalkOmittedThunk {
    thunk: IrId,
    body: IrId,
}

impl TreeWalkOmittedThunk {
    const fn new(thunk: IrId, body: IrId) -> Self {
        Self { thunk, body }
    }

    /// Returns the omitted thunk allocation node.
    pub const fn thunk(self) -> IrId {
        self.thunk
    }

    /// Returns the body whose storage was omitted.
    pub const fn body(self) -> IrId {
        self.body
    }
}

/// A strictness-licensed thunk elision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeWalkThunkElision {
    thunk: IrId,
    body: IrId,
    lowering: BindingLowering,
}

impl TreeWalkThunkElision {
    const fn new(thunk: IrId, body: IrId, lowering: BindingLowering) -> Self {
        Self {
            thunk,
            body,
            lowering,
        }
    }

    /// Returns the thunk allocation node that is not allocated.
    pub const fn thunk(self) -> IrId {
        self.thunk
    }

    /// Returns the body evaluated directly to WHNF.
    pub const fn body(self) -> IrId {
        self.body
    }

    /// Returns the strictness lowering that licensed direct evaluation.
    pub const fn lowering(self) -> BindingLowering {
        self.lowering
    }
}

/// A failure while planning tree-walk thunk allocation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkThunkAllocationError {
    /// The underlying C-8 thunk-sharing preflight rejected the node.
    #[error(transparent)]
    Downgrade(#[from] FrameLocalThunkDowngradeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compile::{
            Cardinality, EffectClass, Escape, ExprFacts, IrArena, IrFacts, IrNode, Strictness,
        },
        syntax::{Span, SymbolTable},
    };

    const BODY: IrId = IrId::new(0);
    const THUNK: IrId = IrId::new(1);

    fn thunk_ir(facts: ExprFacts) -> Ir {
        thunk_ir_with_facts(IrFacts::conservative(2), Some(facts))
    }

    fn thunk_ir_with_facts(mut fact_table: IrFacts, thunk_facts: Option<ExprFacts>) -> Ir {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Int,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Int(1),
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Node(BODY),
                ),
            ],
            Vec::new(),
        );
        if let Some(facts) = thunk_facts
            && let Some(slot) = fact_table.get_mut(THUNK)
        {
            *slot = facts;
        }
        Ir {
            root: THUNK,
            arena,
            facts: fact_table,
            symbols: SymbolTable::new(),
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    #[test]
    fn demand_position_uses_single_entry_only_for_lazy_frame_local_once_thunks() {
        let ir = thunk_ir(ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::NoEscape,
        });

        let plan = tree_walk_thunk_allocation_plan(
            &ir,
            THUNK,
            TreeWalkThunkAllocationContext::DemandPosition,
        )
        .expect("single-entry plan succeeds");

        let TreeWalkThunkAllocationPlan::SingleEntry(single_entry) = plan else {
            panic!("single-entry storage expected");
        };
        assert_eq!(single_entry.thunk(), THUNK);
        assert_eq!(single_entry.body(), BODY);
    }

    #[test]
    fn strict_lowering_elides_instead_of_allocating_single_entry_storage() {
        let ir = thunk_ir(ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Once,
            escape: Escape::NoEscape,
        });

        let plan = tree_walk_thunk_allocation_plan(
            &ir,
            THUNK,
            TreeWalkThunkAllocationContext::DemandPosition,
        )
        .expect("strict elision plan succeeds");

        assert_eq!(
            plan,
            TreeWalkThunkAllocationPlan::ElideToWhnf(TreeWalkThunkElision::new(
                THUNK,
                BODY,
                BindingLowering::Scalar,
            ))
        );
    }

    #[test]
    fn order_sensitive_binding_assembly_keeps_update_slot() {
        let ir = thunk_ir(ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::NoEscape,
        });

        let plan = tree_walk_thunk_allocation_plan(
            &ir,
            THUNK,
            TreeWalkThunkAllocationContext::OrderSensitiveBindingAssembly,
        )
        .expect("order-sensitive plan succeeds");

        assert_eq!(
            plan,
            TreeWalkThunkAllocationPlan::UpdateSlot(TreeWalkThunkUpdateSlot::new(
                THUNK,
                BODY,
                TreeWalkThunkUpdateReason::OrderSensitiveBindingAssembly,
            ))
        );
    }

    #[test]
    fn order_sensitive_binding_assembly_does_not_require_thunk_facts() {
        let ir = thunk_ir_with_facts(IrFacts::conservative(1), None);

        let plan = tree_walk_thunk_allocation_plan(
            &ir,
            THUNK,
            TreeWalkThunkAllocationContext::OrderSensitiveBindingAssembly,
        )
        .expect("order-sensitive plan succeeds without thunk facts");

        assert_eq!(
            plan,
            TreeWalkThunkAllocationPlan::UpdateSlot(TreeWalkThunkUpdateSlot::new(
                THUNK,
                BODY,
                TreeWalkThunkUpdateReason::OrderSensitiveBindingAssembly,
            ))
        );
    }

    #[test]
    fn escaping_lazy_thunk_keeps_update_slot() {
        let ir = thunk_ir(ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::Escapes,
        });

        let plan = tree_walk_thunk_allocation_plan(
            &ir,
            THUNK,
            TreeWalkThunkAllocationContext::DemandPosition,
        )
        .expect("update-slot plan succeeds");

        assert_eq!(
            plan,
            TreeWalkThunkAllocationPlan::UpdateSlot(TreeWalkThunkUpdateSlot::new(
                THUNK,
                BODY,
                TreeWalkThunkUpdateReason::SharingProof(FrameLocalThunkUpdateReason::EscapesFrame,),
            ))
        );
    }

    #[test]
    fn absent_lazy_thunk_is_omitted() {
        let ir = thunk_ir(ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Absent,
            escape: Escape::Escapes,
        });

        let plan = tree_walk_thunk_allocation_plan(
            &ir,
            THUNK,
            TreeWalkThunkAllocationContext::DemandPosition,
        )
        .expect("omission plan succeeds");

        assert_eq!(
            plan,
            TreeWalkThunkAllocationPlan::Omit(TreeWalkOmittedThunk::new(THUNK, BODY))
        );
    }

    #[test]
    fn absent_strict_conflict_keeps_update_slot() {
        let ir = thunk_ir(ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Absent,
            escape: Escape::NoEscape,
        });

        let plan = tree_walk_thunk_allocation_plan(
            &ir,
            THUNK,
            TreeWalkThunkAllocationContext::DemandPosition,
        )
        .expect("conflict plan succeeds");

        assert_eq!(
            plan,
            TreeWalkThunkAllocationPlan::UpdateSlot(TreeWalkThunkUpdateSlot::new(
                THUNK,
                BODY,
                TreeWalkThunkUpdateReason::SharingProof(
                    FrameLocalThunkUpdateReason::AbsentButStrict,
                ),
            ))
        );
    }
}
