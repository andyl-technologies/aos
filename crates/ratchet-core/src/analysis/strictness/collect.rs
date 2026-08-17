//! Demand collection: per-subtree forced-slot maps and lambda summaries.
//!
//! [`collect`] computes, for one subtree, the set of variable slots the
//! subtree's *execution* forces, each with the demand level the force point
//! earns measured from the subtree's start:
//!
//! - `DemandedBeforeEffect` — forced before any observable event of the
//!   subtree's execution can occur;
//! - `Demanded` — forced on every normally-completing execution, but possibly
//!   after an observable event.
//!
//! Slot keys are `(depth, slot)` coordinates relative to the collected node's
//! own frame context; leaving a frame-introducing node consumes its depth-0
//! entries (driving the intra-frame demand fixpoint and the `let`-binding
//! demand marks) and shifts the rest outward.
//!
//! A lambda's parameter summary is exactly the depth-0 entries of its body's
//! collection: the reusable per-lambda demand unit consumed at apply sites.
//!
//! The collection context tracks transparency: [`CollectCtx::Forced`] means
//! the subtree's WHNF is demanded the moment it is evaluated, while
//! [`CollectCtx::Result`] means the value flows out as an enclosing result
//! and may never be forced. The context only matters on the transparent
//! result spine (variables, thunk allocations, `let`/`if` bodies): a variable
//! in result position is *not* forced by this subtree.

use std::rc::Rc;

use crate::builtins::{ArgDemand, demand_signature, lookup_builtin};
use crate::ir::{IrAttrPathSegment, IrData, IrId, IrKind, Strictness};
use crate::syntax::BinOpKind;

use super::{Analysis, StrictnessAnalysisError};

/// A `(depth, slot)` coordinate relative to the collected node.
pub(super) type SlotKey = (u32, u32);

/// Transparency context for one collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum CollectCtx {
    /// The subtree's value is forced as soon as the subtree is evaluated.
    Forced,
    /// The subtree's value flows out as a result and may never be forced.
    Result,
}

/// The forced-slot map for one subtree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct SlotDemand {
    entries: Vec<(SlotKey, Strictness)>,
}

impl SlotDemand {
    fn empty() -> Rc<Self> {
        Rc::new(Self::default())
    }

    fn single(key: SlotKey, level: Strictness) -> Self {
        Self {
            entries: vec![(key, level)],
        }
    }

    /// Returns the demand level for one slot key.
    pub(super) fn level(&self, key: SlotKey) -> Strictness {
        self.entries
            .iter()
            .find(|(entry, _)| *entry == key)
            .map_or(Strictness::Unknown, |(_, level)| *level)
    }

    /// Returns the depth-0 entries (the collected node's innermost frame).
    fn depth_zero(&self) -> impl Iterator<Item = (u32, Strictness)> + '_ {
        self.entries
            .iter()
            .filter(|((depth, _), _)| *depth == 0)
            .map(|((_, slot), level)| (*slot, *level))
    }

    /// Inserts an entry unless the key is already present (first force wins).
    fn insert_first_wins(&mut self, key: SlotKey, level: Strictness) {
        if !self.entries.iter().any(|(entry, _)| *entry == key) {
            self.entries.push((key, level));
        }
    }

    /// Caps every entry to at most [`Strictness::Demanded`].
    fn capped(&self) -> Self {
        Self {
            entries: self
                .entries
                .iter()
                .map(|(key, level)| (*key, cap(*level)))
                .collect(),
        }
    }

    /// Consumes depth-0 entries and shifts the remainder one frame outward.
    fn shifted_out(&self) -> Self {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|((depth, _), _)| *depth > 0)
                .map(|((depth, slot), level)| ((*depth - 1, *slot), *level))
                .collect(),
        }
    }
}

fn cap(level: Strictness) -> Strictness {
    level.min(Strictness::Demanded)
}

/// Sequentially composes child maps in execution order.
///
/// Each step is `(map, step_total)`: entries join first-wins, and once a
/// possibly-effectful step has run, later entries are capped to
/// [`Strictness::Demanded`].
pub(super) struct Sequence {
    result: SlotDemand,
    effect_seen: bool,
}

impl Sequence {
    pub(super) fn new() -> Self {
        Self {
            result: SlotDemand::default(),
            effect_seen: false,
        }
    }

    pub(super) fn push(&mut self, map: &SlotDemand, step_total: bool) {
        for (key, level) in &map.entries {
            let level = if self.effect_seen {
                cap(*level)
            } else {
                *level
            };
            self.result.insert_first_wins(*key, level);
        }
        if !step_total {
            self.effect_seen = true;
        }
    }

    /// Records a possibly-effectful step that contributes no demand.
    pub(super) fn push_opaque_step(&mut self) {
        self.effect_seen = true;
    }

    pub(super) fn finish(self) -> SlotDemand {
        self.result
    }
}

/// Meets two branch maps: a slot is demanded only when both branches demand
/// it, at the weaker of the two levels.
fn branch_meet(then_map: &SlotDemand, else_map: &SlotDemand) -> SlotDemand {
    let mut result = SlotDemand::default();
    for (key, then_level) in &then_map.entries {
        let else_level = else_map.level(*key);
        let met = (*then_level).min(else_level);
        if met != Strictness::Unknown {
            result.insert_first_wins(*key, met);
        }
    }
    result
}

/// Collects the forced-slot map for one subtree.
///
/// Results are memoized per `(node, ctx)`; in-progress nodes (recursion
/// through the intra-frame fixpoint or chased aliases) return an empty map
/// without caching, so cycles fail closed.
pub(super) fn collect(
    analysis: &mut Analysis<'_>,
    id: IrId,
    ctx: CollectCtx,
) -> Result<Rc<SlotDemand>, StrictnessAnalysisError> {
    if let Some(map) = analysis.collect_memo.get(&(id, ctx)) {
        return Ok(Rc::clone(map));
    }
    if analysis.collect_active.contains(&(id, ctx)) {
        return Ok(SlotDemand::empty());
    }
    analysis.collect_active.push((id, ctx));
    let result = collect_uncached(analysis, id, ctx);
    let popped = analysis.collect_active.pop();
    debug_assert_eq!(popped, Some((id, ctx)));
    let map = Rc::new(result?);
    analysis.collect_memo.insert((id, ctx), Rc::clone(&map));
    Ok(map)
}

fn collect_uncached(
    analysis: &mut Analysis<'_>,
    id: IrId,
    ctx: CollectCtx,
) -> Result<SlotDemand, StrictnessAnalysisError> {
    let node = analysis.node(id)?;
    match node.kind {
        IrKind::Int
        | IrKind::Float
        | IrKind::Bool
        | IrKind::Null
        | IrKind::Str
        | IrKind::Path
        | IrKind::Uri
        | IrKind::GlobalVar
        | IrKind::BuiltinAttr
        | IrKind::Lambda
        | IrKind::Formal
        | IrKind::FormalSet
        | IrKind::List => Ok(SlotDemand::default()),
        IrKind::LocalVar => {
            let IrData::Local { slot } = node.data else {
                return Ok(SlotDemand::default());
            };
            Ok(match ctx {
                CollectCtx::Forced => {
                    SlotDemand::single((0, slot), Strictness::DemandedBeforeEffect)
                }
                CollectCtx::Result => SlotDemand::default(),
            })
        }
        IrKind::UpvalVar => {
            let IrData::Upval { depth, slot } = node.data else {
                return Ok(SlotDemand::default());
            };
            Ok(match ctx {
                CollectCtx::Forced => {
                    SlotDemand::single((depth, slot), Strictness::DemandedBeforeEffect)
                }
                CollectCtx::Result => SlotDemand::default(),
            })
        }
        IrKind::ThunkAlloc => {
            let IrData::Node(body) = node.data else {
                return Ok(SlotDemand::default());
            };
            match ctx {
                // Forced immediately after allocation: the body runs here.
                CollectCtx::Forced => Ok((*collect(analysis, body, CollectCtx::Forced)?).clone()),
                // Deferred: nothing is forced by this subtree.
                CollectCtx::Result => Ok(SlotDemand::default()),
            }
        }
        IrKind::SearchPath => {
            let IrData::SearchPath {
                search_path: Some(search_path),
                ..
            } = node.data
            else {
                return Ok(SlotDemand::default());
            };
            Ok((*collect(analysis, search_path, CollectCtx::Forced)?).clone())
        }
        IrKind::Let => {
            let IrData::Let { bindings, body, .. } = node.data else {
                return Ok(SlotDemand::default());
            };
            let inner = frame_demand_fixpoint(analysis, id, bindings, Some((body, ctx)), false)?;
            Ok(inner.shifted_out())
        }
        IrKind::AttrSet => {
            let IrData::AttrSet {
                bindings,
                recursive,
                ..
            } = node.data
            else {
                return Ok(SlotDemand::default());
            };
            if recursive {
                let inner = frame_demand_fixpoint(analysis, id, bindings, None, true)?;
                Ok(inner.shifted_out())
            } else {
                let mut sequence = Sequence::new();
                let entries = analysis.bindings(id, bindings)?;
                for binding in entries {
                    if let IrAttrPathSegment::Dynamic(key) = binding.key {
                        let map = collect(analysis, key, CollectCtx::Forced)?;
                        sequence.push(&map, analysis.total(key));
                    }
                }
                Ok(sequence.finish())
            }
        }
        IrKind::With => {
            let IrData::Pair { second, .. } = node.data else {
                return Ok(SlotDemand::default());
            };
            // The scope expression is allocated lazily; only the body runs.
            Ok((*collect(analysis, second, ctx)?).clone())
        }
        IrKind::Assert => {
            let IrData::Pair {
                first: condition,
                second: body,
            } = node.data
            else {
                return Ok(SlotDemand::default());
            };
            let mut sequence = Sequence::new();
            let condition_map = collect(analysis, condition, CollectCtx::Forced)?;
            sequence.push(&condition_map, analysis.total(condition));
            // A false condition raises an observable error before the body,
            // so body demand can never stay before-effect.
            sequence.push_opaque_step();
            let body_map = collect(analysis, body, ctx)?;
            sequence.push(&body_map, false);
            Ok(sequence.finish())
        }
        IrKind::If => {
            let IrData::Triple {
                first: condition,
                second: then_branch,
                third: else_branch,
            } = node.data
            else {
                return Ok(SlotDemand::default());
            };
            let mut sequence = Sequence::new();
            let condition_map = collect(analysis, condition, CollectCtx::Forced)?;
            sequence.push(&condition_map, analysis.total(condition));
            let then_map = collect(analysis, then_branch, ctx)?;
            let else_map = collect(analysis, else_branch, ctx)?;
            sequence.push(&branch_meet(&then_map, &else_map), false);
            Ok(sequence.finish())
        }
        IrKind::BinOp => {
            let IrData::Binary { op, lhs, rhs } = node.data else {
                return Ok(SlotDemand::default());
            };
            let mut sequence = Sequence::new();
            match op {
                BinOpKind::And | BinOpKind::Or | BinOpKind::Impl => {
                    let map = collect(analysis, lhs, CollectCtx::Forced)?;
                    sequence.push(&map, analysis.total(lhs));
                }
                BinOpKind::PipeRight => {
                    let map = collect(analysis, rhs, CollectCtx::Forced)?;
                    sequence.push(&map, analysis.total(rhs));
                }
                BinOpKind::PipeLeft => {
                    let map = collect(analysis, lhs, CollectCtx::Forced)?;
                    sequence.push(&map, analysis.total(lhs));
                }
                BinOpKind::Add
                | BinOpKind::Sub
                | BinOpKind::Mul
                | BinOpKind::Div
                | BinOpKind::Concat
                | BinOpKind::Update
                | BinOpKind::Lt
                | BinOpKind::Gt
                | BinOpKind::Le
                | BinOpKind::Ge
                | BinOpKind::Eq
                | BinOpKind::Ne => {
                    let lhs_map = collect(analysis, lhs, CollectCtx::Forced)?;
                    sequence.push(&lhs_map, analysis.total(lhs));
                    let rhs_map = collect(analysis, rhs, CollectCtx::Forced)?;
                    sequence.push(&rhs_map, analysis.total(rhs));
                }
            }
            Ok(sequence.finish())
        }
        IrKind::UnaryOp => {
            let IrData::Unary { operand, .. } = node.data else {
                return Ok(SlotDemand::default());
            };
            Ok((*collect(analysis, operand, CollectCtx::Forced)?).clone())
        }
        IrKind::Interp => {
            let children: &[IrId] = match node.data {
                IrData::Node(ref child) => std::slice::from_ref(child),
                IrData::Children(children) => analysis.child_ids(id, children)?,
                _ => &[],
            };
            let mut sequence = Sequence::new();
            for child in children {
                let map = collect(analysis, *child, CollectCtx::Forced)?;
                sequence.push(&map, analysis.total(*child));
            }
            Ok(sequence.finish())
        }
        IrKind::Select => {
            let IrData::Select { receiver, path, .. } = node.data else {
                return Ok(SlotDemand::default());
            };
            collect_lookup(analysis, id, receiver, path)
        }
        IrKind::HasAttr => {
            let IrData::HasAttr { receiver, path, .. } = node.data else {
                return Ok(SlotDemand::default());
            };
            collect_lookup(analysis, id, receiver, path)
        }
        IrKind::Apply => {
            let IrData::Pair {
                first: function,
                second: argument,
            } = node.data
            else {
                return Ok(SlotDemand::default());
            };
            collect_apply(analysis, ctx, function, argument)
        }
        IrKind::PrimOp => collect_primop(analysis, id, node.data, ctx),
    }
}

/// Collects a `select`/`?` lookup: the receiver and the leading dynamic
/// segment, order-free capped against each other.
fn collect_lookup(
    analysis: &mut Analysis<'_>,
    id: IrId,
    receiver: IrId,
    path: crate::ir::IrAttrPathId,
) -> Result<SlotDemand, StrictnessAnalysisError> {
    let leading = match analysis.attr_path(id, path)?.first() {
        Some(IrAttrPathSegment::Dynamic(segment)) => Some(*segment),
        _ => None,
    };
    let receiver_map = collect(analysis, receiver, CollectCtx::Forced)?;
    let receiver_total = analysis.total(receiver);
    let mut sequence = Sequence::new();
    match leading {
        Some(segment) => {
            let segment_map = collect(analysis, segment, CollectCtx::Forced)?;
            let segment_total = analysis.total(segment);
            // Force order between receiver and leading segment is not part of
            // the frozen surface here, so each side is capped unless the
            // other cannot effect.
            let receiver_entry = if segment_total {
                (*receiver_map).clone()
            } else {
                receiver_map.capped()
            };
            let segment_entry = if receiver_total {
                (*segment_map).clone()
            } else {
                segment_map.capped()
            };
            sequence.push(&receiver_entry, receiver_total);
            sequence.push(&segment_entry, segment_total);
        }
        None => sequence.push(&receiver_map, receiver_total),
    }
    Ok(sequence.finish())
}

/// Collects one application: the forced function expression plus the
/// argument's contribution gated by the callee's parameter summary.
fn collect_apply(
    analysis: &mut Analysis<'_>,
    ctx: CollectCtx,
    function: IrId,
    argument: IrId,
) -> Result<SlotDemand, StrictnessAnalysisError> {
    let mut sequence = Sequence::new();
    let function_map = collect(analysis, function, CollectCtx::Forced)?;
    sequence.push(&function_map, analysis.total(function));

    // What the argument's evaluation itself runs right now (non-thunk
    // argument expressions execute at the apply).
    let immediate = collect(analysis, argument, CollectCtx::Result)?;
    sequence.push(&immediate, false);

    // What the callee's execution forces later, gated per parameter summary.
    // Only a syntactically literal callee is used here; the demand walk
    // performs the frame-stack chase for variable-bound callees.
    let summary = literal_callee_argument_demand(analysis, function)?;
    let summary_level = match summary {
        Some(LambdaArgumentDemand::Level(level)) => level,
        // The parameter is only forced when the call's own result is: the
        // demand transfers exactly when this apply is itself forced.
        Some(LambdaArgumentDemand::IfResultForced(level)) => match ctx {
            CollectCtx::Forced => level,
            CollectCtx::Result => Strictness::Unknown,
        },
        None => Strictness::Unknown,
    };
    if summary_level != Strictness::Unknown {
        let deferred = collect(analysis, argument, CollectCtx::Forced)?;
        let mut gated = SlotDemand::default();
        for (key, level) in &deferred.entries {
            let level = (*level).min(summary_level);
            if level != Strictness::Unknown {
                gated.insert_first_wins(*key, level);
            }
        }
        sequence.push(&gated, false);
    }
    Ok(sequence.finish())
}

/// Returns the argument demand for a syntactically literal lambda callee, or
/// `None` when the callee is not a literal lambda.
fn literal_callee_argument_demand(
    analysis: &mut Analysis<'_>,
    function: IrId,
) -> Result<Option<LambdaArgumentDemand>, StrictnessAnalysisError> {
    let node = analysis.node(function)?;
    let IrData::Lambda { .. } = node.data else {
        return Ok(None);
    };
    Ok(Some(lambda_argument_demand(analysis, function)?))
}

/// The demand a lambda places on its argument: the reusable per-lambda
/// demand summary consumed at apply sites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LambdaArgumentDemand {
    /// The body's execution forces the parameter at this level (relative to
    /// body start), regardless of what happens to the call's result.
    Level(Strictness),
    /// The parameter is forced (at this level) only when the call's own
    /// result is forced — `x: x`-shaped transparent result spines. The
    /// demand transfers from the caller's position.
    IfResultForced(Strictness),
}

/// Returns the demand a lambda places on its argument.
///
/// Formal-set patterns force the argument to an attribute set during pattern
/// matching, so a validated formal-set lambda demands its argument before any
/// effect. Simple formals consult the body's parameter summary, falling back
/// to the transparent result spine (`x: x`-shaped bodies) whose demand
/// transfers from the caller.
///
/// # Errors
///
/// Returns [`StrictnessAnalysisError`] when the lambda payload, its pattern,
/// a formal symbol, or the referenced frame is malformed.
pub(super) fn lambda_argument_demand(
    analysis: &mut Analysis<'_>,
    lambda: IrId,
) -> Result<LambdaArgumentDemand, StrictnessAnalysisError> {
    let node = analysis.node(lambda)?;
    let IrData::Lambda {
        pattern: pattern_id,
        body,
        frame,
    } = node.data
    else {
        return Ok(LambdaArgumentDemand::Level(Strictness::Unknown));
    };
    let pattern = analysis.node(pattern_id)?;
    match pattern.kind {
        IrKind::Formal => {
            let IrData::Formal { default: None, .. } = pattern.data else {
                return Ok(LambdaArgumentDemand::Level(Strictness::Unknown));
            };
            let summary = collect(analysis, body, CollectCtx::Result)?;
            let level = summary.level((0, 0));
            if level != Strictness::Unknown {
                return Ok(LambdaArgumentDemand::Level(level));
            }
            // The body alone does not force the parameter; check whether a
            // forced call result would (transparent result spines).
            let forced_summary = collect(analysis, body, CollectCtx::Forced)?;
            let forced_level = forced_summary.level((0, 0));
            if forced_level != Strictness::Unknown {
                return Ok(LambdaArgumentDemand::IfResultForced(forced_level));
            }
            Ok(LambdaArgumentDemand::Level(Strictness::Unknown))
        }
        IrKind::FormalSet => {
            if formal_set_pattern_forces_argument(analysis, lambda, pattern_id, pattern, frame)? {
                Ok(LambdaArgumentDemand::Level(
                    Strictness::DemandedBeforeEffect,
                ))
            } else {
                Ok(LambdaArgumentDemand::Level(Strictness::Unknown))
            }
        }
        _ => Ok(LambdaArgumentDemand::Level(Strictness::Unknown)),
    }
}

/// Validates a formal-set pattern and returns whether binding it must force
/// the argument to an attribute set.
fn formal_set_pattern_forces_argument(
    analysis: &Analysis<'_>,
    lambda: IrId,
    pattern_id: IrId,
    pattern: crate::ir::IrNode,
    frame: Option<crate::FrameId>,
) -> Result<bool, StrictnessAnalysisError> {
    let Some(frame) = frame else {
        return Ok(false);
    };
    let IrData::FormalSet { formals, alias, .. } = pattern.data else {
        return Err(StrictnessAnalysisError::InvalidPayload {
            id: pattern_id,
            kind: pattern.kind,
            expected: super::expected_payload(pattern.kind),
        });
    };
    let formal_ids = analysis.child_ids(pattern_id, formals)?;
    let mut names = Vec::new();
    for &formal_id in formal_ids {
        let formal = analysis.node(formal_id)?;
        if formal.kind != IrKind::Formal {
            return Err(StrictnessAnalysisError::InvalidPayload {
                id: formal_id,
                kind: formal.kind,
                expected: super::expected_payload(IrKind::Formal),
            });
        }
        let IrData::Formal { name, .. } = formal.data else {
            return Err(StrictnessAnalysisError::InvalidPayload {
                id: formal_id,
                kind: formal.kind,
                expected: super::expected_payload(formal.kind),
            });
        };
        if analysis.ir.symbols.resolve(name).is_none() {
            return Err(StrictnessAnalysisError::InvalidSymbol {
                id: formal_id,
                symbol: name,
            });
        }
        names.push(name);
    }
    if let Some(alias) = alias
        && analysis.ir.symbols.resolve(alias).is_none()
    {
        return Err(StrictnessAnalysisError::InvalidSymbol {
            id: lambda,
            symbol: alias,
        });
    }
    let alias_slot = alias.filter(|alias| !names.contains(alias));
    let pattern_slots = names.len() + usize::from(alias_slot.is_some());
    let slot_count = analysis
        .ir
        .frames
        .get(frame.index())
        .ok_or(StrictnessAnalysisError::InvalidFrame { id: lambda, frame })?
        .slot_count as usize;
    Ok(slot_count == pattern_slots)
}

/// Runs the intra-frame demand fixpoint for one `let` or `rec { }` frame and
/// marks demanded binding values.
///
/// Demand seeded by the body (and dynamic keys) flows into binding values:
/// each demanded slot's value contributes its own forced-slot map (capped to
/// [`Strictness::Demanded`], since the force point is deferred to the slot's
/// first use), iterated until no new same-frame slots appear. Demanded
/// binding value nodes are marked [`Strictness::Demanded`] as fan-out hints.
/// The returned map is in frame-inner coordinates.
fn frame_demand_fixpoint(
    analysis: &mut Analysis<'_>,
    id: IrId,
    bindings: crate::ir::IrBindingSlice,
    body: Option<(IrId, CollectCtx)>,
    recursive_attrs: bool,
) -> Result<SlotDemand, StrictnessAnalysisError> {
    let entries: Vec<(Option<IrId>, IrId)> = analysis
        .bindings(id, bindings)?
        .iter()
        .map(|binding| {
            let key = match binding.key {
                IrAttrPathSegment::Dynamic(key) => Some(key),
                IrAttrPathSegment::Static(_) => None,
            };
            (key, binding.value)
        })
        .collect();

    let mut demanded = SlotDemand::default();
    if recursive_attrs {
        // Dynamic keys are forced during assembly, inside the frame.
        let mut sequence = Sequence::new();
        for (key, _) in &entries {
            if let Some(key) = key {
                let map = collect(analysis, *key, CollectCtx::Forced)?;
                sequence.push(&map, analysis.total(*key));
            }
        }
        demanded = sequence.finish();
    }
    if let Some((body, ctx)) = body {
        // A `let` body runs directly after binding assembly, which only
        // allocates, so body demand keeps its levels uncapped.
        let body_map = collect(analysis, body, ctx)?;
        for (key, level) in &body_map.entries {
            demanded.insert_first_wins(*key, *level);
        }
    }

    // Slot values for a frame: `let` slots are all bindings in order;
    // `rec { }` slots are the static bindings in order.
    let slot_values: Vec<IrId> = if recursive_attrs {
        entries
            .iter()
            .filter(|(key, _)| key.is_none())
            .map(|(_, value)| *value)
            .collect()
    } else {
        entries.iter().map(|(_, value)| *value).collect()
    };

    let mut visited = vec![false; slot_values.len()];
    loop {
        let mut changed = false;
        let pending: Vec<u32> = demanded
            .depth_zero()
            .map(|(slot, _)| slot)
            .filter(|slot| {
                usize::try_from(*slot).is_ok_and(|slot| slot < visited.len() && !visited[slot])
            })
            .collect();
        for slot in pending {
            let index = slot as usize;
            visited[index] = true;
            changed = true;
            let value = slot_values[index];
            analysis.mark(value, Strictness::Demanded);
            // The value's own forcing is deferred to the slot's first use.
            let value_map = collect(analysis, value, CollectCtx::Forced)?.capped();
            for (key, level) in &value_map.entries {
                demanded.insert_first_wins(*key, *level);
            }
        }
        if !changed {
            break;
        }
    }
    Ok(demanded)
}

fn collect_primop(
    analysis: &mut Analysis<'_>,
    id: IrId,
    data: IrData,
    ctx: CollectCtx,
) -> Result<SlotDemand, StrictnessAnalysisError> {
    match data {
        IrData::PrimOp { symbol, args } => {
            let args = analysis.child_ids(id, args)?;
            let name = analysis
                .ir
                .symbols
                .resolve(symbol)
                .ok_or(StrictnessAnalysisError::InvalidSymbol { id, symbol })?;
            let Some(builtin) = lookup_builtin(name) else {
                return Ok(SlotDemand::default());
            };
            // The derivationStrict serializer forces the argument, then every
            // attribute value of a direct literal argument in its verified
            // (name-first) order; compose those forces sequentially instead
            // of using the generic per-argument treatment.
            if matches!(
                builtin.execution(),
                crate::builtins::BuiltinExecution::DerivationStrict
            ) && let [argument] = args
            {
                return collect_derivation_strict(analysis, *argument);
            }
            let signature = demand_signature(builtin.execution());
            // Force order across builtin arguments is not part of the frozen
            // surface, so each contribution is capped unless every *other*
            // argument is total.
            let mut contributions = Vec::new();
            for (index, arg) in args.iter().enumerate() {
                let map = match signature.arg(index) {
                    ArgDemand::Forced => collect(analysis, *arg, CollectCtx::Forced)?,
                    // The builtin returns this argument's value as its own
                    // result, so the position mirrors the call's context: a
                    // forced call forces the returned value immediately.
                    ArgDemand::Result { after_effect } => {
                        let map = collect(analysis, *arg, ctx)?;
                        if after_effect {
                            Rc::new(map.capped())
                        } else {
                            map
                        }
                    }
                    // S4 / error-attribution barriers: the argument is
                    // evaluated, but demand never propagates through it.
                    ArgDemand::ForcedUnderCatch | ArgDemand::Barred | ArgDemand::Lazy => continue,
                };
                contributions.push((index, map));
            }
            let mut result = SlotDemand::default();
            for (index, map) in &contributions {
                let others_total = args
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| other != index)
                    .all(|(_, other)| analysis.total(*other));
                let map = if others_total {
                    (**map).clone()
                } else {
                    map.capped()
                };
                for (key, level) in &map.entries {
                    result.insert_first_wins(*key, *level);
                }
            }
            Ok(result)
        }
        IrData::DialectNode { op, argument } => {
            if op == super::derivation::DERIVATION_STRICT_DIALECT_OP {
                return collect_derivation_strict(analysis, argument);
            }
            Ok((*collect(analysis, argument, CollectCtx::Forced)?).clone())
        }
        _ => Ok(SlotDemand::default()),
    }
}

/// Composes the `derivationStrict` argument force with the boundary's
/// per-attribute forces of a direct literal argument.
fn collect_derivation_strict(
    analysis: &mut Analysis<'_>,
    argument: IrId,
) -> Result<SlotDemand, StrictnessAnalysisError> {
    let mut sequence = Sequence::new();
    let base = collect(analysis, argument, CollectCtx::Forced)?;
    sequence.push(&base, analysis.total(argument));
    let boundary = super::derivation::collect_derivation_strict_boundary(analysis, argument)?;
    sequence.push(&boundary, false);
    Ok(sequence.finish())
}
