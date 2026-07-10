//! Persisted lambda demand summaries and derivation attribute provenance.
//!
//! The ordinary demand walk can chase callees only inside one lowered module.
//! This pass records the same parameter facts on lambda patterns so a runtime
//! closure imported from another module can transfer them to its caller. It
//! also follows right-biased attribute updates into `removeAttrs alias [...]`;
//! that shape describes the ellipsis attributes forwarded by `mkDerivation`
//! without claiming that an unknown right operand preserves left values.

use std::collections::BTreeSet;

use crate::builtins::{ArgDemand, demand_signature, lookup_builtin};
use crate::ir::{
    Escape, IrAttrPathSegment, IrData, IrId, IrKind, LambdaAttrKeys, LambdaAttrValueSummary,
    LambdaCallSummary, LambdaDemand, LambdaFormalSummary, Strictness,
};
use crate::syntax::{BinOpKind, Symbol};

use super::collect::{CollectCtx, LambdaArgumentDemand, collect, lambda_argument_demand};
use super::derivation::DERIVATION_STRICT_DIALECT_OP;
use super::frames::{ChasedCallee, FrameScope, chase_callee, resolve_slot};
use super::{Analysis, StrictnessAnalysisError};

const REMOVE_ATTRS: &[u8] = b"removeAttrs";
const DERIVATION: &[u8] = b"derivation";

/// Computes sparse formal-set lambda summaries in pattern-id order.
///
/// The runtime consumer transfers facts only into statically shaped attribute
/// arguments. Simple-formal lambdas have no per-key contract, so retaining
/// them would add analysis, sidecar, and lookup cost without licensing a
/// binding-assembly optimization.
pub(super) fn compute(
    analysis: &mut Analysis<'_>,
) -> Result<Vec<LambdaCallSummary>, StrictnessAnalysisError> {
    let lambdas: Vec<IrId> = analysis
        .ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            let IrData::Lambda { pattern, .. } = node.data else {
                return None;
            };
            (node.kind == IrKind::Lambda
                && analysis
                    .ir
                    .arena
                    .node(pattern)
                    .is_some_and(|pattern| pattern.kind == IrKind::FormalSet))
            .then(|| IrId::new(index as u32))
        })
        .collect();
    let mut summaries = Vec::new();
    summaries.reserve(lambdas.len());
    for lambda in lambdas {
        summaries.push(compute_lambda(analysis, lambda)?);
    }
    summaries.sort_unstable_by_key(|summary| summary.pattern.as_u32());
    Ok(summaries)
}

fn compute_lambda(
    analysis: &mut Analysis<'_>,
    lambda: IrId,
) -> Result<LambdaCallSummary, StrictnessAnalysisError> {
    let node = analysis.node(lambda)?;
    let IrData::Lambda { pattern, body, .. } = node.data else {
        return Err(StrictnessAnalysisError::InvalidPayload {
            id: lambda,
            kind: node.kind,
            expected: super::expected_payload(node.kind),
        });
    };
    let pattern_node = analysis.node(pattern)?;
    let formal_count = match pattern_node.data {
        IrData::Formal { .. } => 1,
        IrData::FormalSet { formals, alias, .. } => {
            let names = formal_names(analysis, pattern, formals)?;
            names.len() + usize::from(alias.is_some_and(|alias| !names.contains(&alias)))
        }
        _ => 0,
    };
    let immediate = collect(analysis, body, CollectCtx::Result)?;
    let forced = collect(analysis, body, CollectCtx::Forced)?;
    let mut formals = Vec::new();
    formals.reserve(formal_count);
    for slot in 0..formal_count {
        let slot = slot as u32;
        let immediate_level = immediate.level((0, slot));
        let demand = if immediate_level.is_demanded() {
            LambdaDemand::Unconditional(immediate_level)
        } else {
            LambdaDemand::IfResultForced(forced.level((0, slot)))
        };
        formals.push(LambdaFormalSummary {
            demand,
            escape: Escape::Escapes,
        });
    }
    let argument_demand = match lambda_argument_demand(analysis, lambda)? {
        LambdaArgumentDemand::Level(level) => LambdaDemand::Unconditional(level),
        LambdaArgumentDemand::IfResultForced(level) => LambdaDemand::IfResultForced(level),
    };
    let mut attr_values = Vec::new();
    if let Some(alias_slot) = formal_alias_slot(analysis, pattern, pattern_node)? {
        let mut stack = vec![FrameScope::for_lambda(lambda)];
        let immediate = trace(analysis, body, CollectCtx::Result, &mut stack, lambda)?;
        let forced = trace(analysis, body, CollectCtx::Forced, &mut stack, lambda)?;
        append_alias_rules(
            &mut attr_values,
            immediate.rules,
            alias_slot,
            LambdaDemand::Unconditional(Strictness::Demanded),
        );
        append_alias_rules(
            &mut attr_values,
            forced.rules,
            alias_slot,
            LambdaDemand::IfResultForced(Strictness::Demanded),
        );
    }
    Ok(LambdaCallSummary {
        pattern,
        argument_demand,
        argument_escape: Escape::Escapes,
        formals: formals.into_boxed_slice(),
        attr_values: attr_values.into_boxed_slice(),
    })
}

fn append_alias_rules(
    output: &mut Vec<LambdaAttrValueSummary>,
    rules: Vec<SourceRule>,
    alias_slot: u32,
    demand: LambdaDemand,
) {
    for rule in rules {
        if rule.slot != alias_slot || rule.keys.is_empty() {
            continue;
        }
        output.push(LambdaAttrValueSummary {
            keys: rule.keys.into_fact(),
            demand,
            escape: Escape::Escapes,
        });
    }
}

fn formal_names(
    analysis: &Analysis<'_>,
    pattern: IrId,
    formals: crate::ir::IrChildSlice,
) -> Result<Vec<Symbol>, StrictnessAnalysisError> {
    let mut names = Vec::new();
    for formal in analysis.child_ids(pattern, formals)? {
        let node = analysis.node(*formal)?;
        let IrData::Formal { name, .. } = node.data else {
            return Err(StrictnessAnalysisError::InvalidPayload {
                id: *formal,
                kind: node.kind,
                expected: super::expected_payload(IrKind::Formal),
            });
        };
        names.push(name);
    }
    Ok(names)
}

fn formal_alias_slot(
    analysis: &Analysis<'_>,
    pattern: IrId,
    node: crate::ir::IrNode,
) -> Result<Option<u32>, StrictnessAnalysisError> {
    let IrData::FormalSet { formals, alias, .. } = node.data else {
        return Ok(None);
    };
    let Some(alias) = alias else {
        return Ok(None);
    };
    let names = formal_names(analysis, pattern, formals)?;
    if let Some(index) = names.iter().position(|name| *name == alias) {
        Ok(Some(index as u32))
    } else {
        Ok(Some(names.len() as u32))
    }
}

#[derive(Clone, Debug, Default)]
struct Trace {
    rules: Vec<SourceRule>,
}

impl Trace {
    fn union(mut self, other: Self) -> Self {
        for rule in other.rules {
            self.insert(rule);
        }
        self
    }

    fn insert(&mut self, rule: SourceRule) {
        if let Some(existing) = self.rules.iter_mut().find(|entry| entry.slot == rule.slot) {
            existing.keys = existing.keys.union(&rule.keys);
        } else {
            self.rules.push(rule);
        }
    }

    fn meet(&self, other: &Self) -> Self {
        let mut result = Self::default();
        for lhs in &self.rules {
            if let Some(rhs) = other.rules.iter().find(|rhs| rhs.slot == lhs.slot) {
                let keys = lhs.keys.intersection(&rhs.keys);
                if !keys.is_empty() {
                    result.insert(SourceRule {
                        slot: lhs.slot,
                        keys,
                    });
                }
            }
        }
        result
    }
}

fn trace(
    analysis: &mut Analysis<'_>,
    id: IrId,
    ctx: CollectCtx,
    stack: &mut Vec<FrameScope>,
    lambda: IrId,
) -> Result<Trace, StrictnessAnalysisError> {
    let key = (lambda, id, ctx);
    if analysis.summary_trace_active.contains(&key) {
        return Ok(Trace::default());
    }
    analysis.summary_trace_active.push(key);
    let result = trace_uncached(analysis, id, ctx, stack, lambda);
    let popped = analysis.summary_trace_active.pop();
    debug_assert_eq!(popped, Some(key));
    result
}

fn trace_uncached(
    analysis: &mut Analysis<'_>,
    id: IrId,
    ctx: CollectCtx,
    stack: &mut Vec<FrameScope>,
    lambda: IrId,
) -> Result<Trace, StrictnessAnalysisError> {
    let node = analysis.node(id)?;
    match node.kind {
        IrKind::ThunkAlloc => match (ctx, node.data) {
            (CollectCtx::Forced, IrData::Node(body)) => trace(analysis, body, ctx, stack, lambda),
            _ => Ok(Trace::default()),
        },
        IrKind::LocalVar | IrKind::UpvalVar if ctx == CollectCtx::Forced => {
            let target = variable_target_scope(stack, node.data);
            let Some((scope, slot)) = target else {
                return Ok(Trace::default());
            };
            if scope == FrameScope::for_lambda(lambda) {
                return Ok(Trace::default());
            }
            let Some(value) = resolve_slot(analysis, scope, slot)? else {
                return Ok(Trace::default());
            };
            trace(analysis, value, CollectCtx::Forced, stack, lambda)
        }
        IrKind::Let => {
            let IrData::Let { bindings, body, .. } = node.data else {
                return Ok(Trace::default());
            };
            stack.push(FrameScope::for_let(id, bindings));
            let result = trace(analysis, body, ctx, stack, lambda);
            stack.pop();
            result
        }
        IrKind::Assert => {
            let IrData::Pair { first, second } = node.data else {
                return Ok(Trace::default());
            };
            let first = trace(analysis, first, CollectCtx::Forced, stack, lambda)?;
            Ok(first.union(trace(analysis, second, ctx, stack, lambda)?))
        }
        IrKind::If => {
            let IrData::Triple {
                first,
                second,
                third,
            } = node.data
            else {
                return Ok(Trace::default());
            };
            let condition = trace(analysis, first, CollectCtx::Forced, stack, lambda)?;
            let then_trace = trace(analysis, second, ctx, stack, lambda)?;
            let else_trace = trace(analysis, third, ctx, stack, lambda)?;
            Ok(condition.union(then_trace.meet(&else_trace)))
        }
        IrKind::BinOp => {
            let IrData::Binary { op, lhs, rhs } = node.data else {
                return Ok(Trace::default());
            };
            let lhs = trace(analysis, lhs, CollectCtx::Forced, stack, lambda)?;
            if matches!(op, BinOpKind::And | BinOpKind::Or | BinOpKind::Impl) {
                Ok(lhs)
            } else if matches!(op, BinOpKind::PipeRight) {
                trace(analysis, rhs, CollectCtx::Forced, stack, lambda)
            } else {
                Ok(lhs.union(trace(analysis, rhs, CollectCtx::Forced, stack, lambda)?))
            }
        }
        IrKind::UnaryOp => match node.data {
            IrData::Unary { operand, .. } => {
                trace(analysis, operand, CollectCtx::Forced, stack, lambda)
            }
            _ => Ok(Trace::default()),
        },
        IrKind::Interp => {
            let children: &[IrId] = match node.data {
                IrData::Node(ref child) => std::slice::from_ref(child),
                IrData::Children(children) => analysis.child_ids(id, children)?,
                _ => &[],
            };
            let mut result = Trace::default();
            for child in children {
                result = result.union(trace(analysis, *child, CollectCtx::Forced, stack, lambda)?);
            }
            Ok(result)
        }
        IrKind::Select | IrKind::HasAttr => {
            let receiver = match node.data {
                IrData::Select { receiver, .. } | IrData::HasAttr { receiver, .. } => receiver,
                _ => return Ok(Trace::default()),
            };
            trace(analysis, receiver, CollectCtx::Forced, stack, lambda)
        }
        IrKind::With => match node.data {
            IrData::Pair { second, .. } => trace(analysis, second, ctx, stack, lambda),
            _ => Ok(Trace::default()),
        },
        IrKind::Apply => trace_apply(analysis, node.data, ctx, stack, lambda),
        IrKind::PrimOp => trace_primop(analysis, id, node.data, ctx, stack, lambda),
        IrKind::AttrSet => {
            let IrData::AttrSet {
                bindings,
                recursive,
                ..
            } = node.data
            else {
                return Ok(Trace::default());
            };
            let scope = recursive.then(|| FrameScope::for_rec_attrs(analysis, id, bindings));
            if let Some(scope) = scope {
                stack.push(scope);
            }
            let mut result = Trace::default();
            for binding in analysis.bindings(id, bindings)? {
                if let IrAttrPathSegment::Dynamic(key) = binding.key {
                    result = result.union(trace(analysis, key, CollectCtx::Forced, stack, lambda)?);
                }
            }
            if scope.is_some() {
                stack.pop();
            }
            Ok(result)
        }
        _ => Ok(Trace::default()),
    }
}

fn trace_apply(
    analysis: &mut Analysis<'_>,
    data: IrData,
    ctx: CollectCtx,
    stack: &mut Vec<FrameScope>,
    lambda: IrId,
) -> Result<Trace, StrictnessAnalysisError> {
    let IrData::Pair { first, second } = data else {
        return Ok(Trace::default());
    };
    let mut result = trace(analysis, first, CollectCtx::Forced, stack, lambda)?;
    let demand = match chase_callee(analysis, stack, first)? {
        ChasedCallee::Lambda(callee) => lambda_argument_demand(analysis, callee)?,
        ChasedCallee::Unknown => return Ok(result),
    };
    let forced = match demand {
        LambdaArgumentDemand::Level(level) => level.is_demanded(),
        LambdaArgumentDemand::IfResultForced(level) => {
            ctx == CollectCtx::Forced && level.is_demanded()
        }
    };
    if forced {
        result = result.union(trace(analysis, second, CollectCtx::Forced, stack, lambda)?);
    }
    Ok(result)
}

fn trace_primop(
    analysis: &mut Analysis<'_>,
    id: IrId,
    data: IrData,
    ctx: CollectCtx,
    stack: &mut Vec<FrameScope>,
    lambda: IrId,
) -> Result<Trace, StrictnessAnalysisError> {
    if let IrData::DialectNode { op, argument } = data {
        let mut result = trace(analysis, argument, CollectCtx::Forced, stack, lambda)?;
        if op == DERIVATION_STRICT_DIALECT_OP {
            for rule in attr_sources(analysis, argument, KeyDomain::all(), stack, lambda, 0)?.rules
            {
                result.insert(rule);
            }
        }
        return Ok(result);
    }
    let IrData::PrimOp { symbol, args } = data else {
        return Ok(Trace::default());
    };
    let Some(name) = analysis.ir.symbols.resolve(symbol) else {
        return Err(StrictnessAnalysisError::InvalidSymbol { id, symbol });
    };
    let Some(builtin) = lookup_builtin(name) else {
        return Ok(Trace::default());
    };
    let children = analysis.child_ids(id, args)?.to_vec();
    let signature = demand_signature(builtin.execution());
    let mut result = Trace::default();
    for (index, child) in children.into_iter().enumerate() {
        let child_ctx = match signature.arg(index) {
            ArgDemand::Forced => Some(CollectCtx::Forced),
            ArgDemand::Result { .. } => Some(ctx),
            ArgDemand::Lazy => Some(CollectCtx::Result),
            ArgDemand::ForcedUnderCatch | ArgDemand::Barred => None,
        };
        if let Some(child_ctx) = child_ctx {
            result = result.union(trace(analysis, child, child_ctx, stack, lambda)?);
        }
    }
    // The Nix-source `derivation` wrapper only reaches its serializer when
    // the wrapper result is forced. `compute_lambda` invokes this trace once
    // in result context and once in forced context, so adding provenance only
    // here produces the required `IfResultForced` summary instead of an
    // unsound unconditional demand.
    if name == DERIVATION && ctx == CollectCtx::Forced {
        let args = analysis.child_ids(id, args)?;
        if let [argument] = args {
            for rule in attr_sources(analysis, *argument, KeyDomain::all(), stack, lambda, 0)?.rules
            {
                result.insert(rule);
            }
        }
    }
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum KeyDomain {
    Only(BTreeSet<Symbol>),
    AllExcept(BTreeSet<Symbol>),
}

impl KeyDomain {
    pub(super) fn all() -> Self {
        Self::AllExcept(BTreeSet::new())
    }

    fn is_empty(&self) -> bool {
        matches!(self, Self::Only(keys) if keys.is_empty())
    }

    fn contains(&self, key: Symbol) -> bool {
        match self {
            Self::Only(keys) => keys.contains(&key),
            Self::AllExcept(keys) => !keys.contains(&key),
        }
    }

    fn intersection(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Only(lhs), Self::Only(rhs)) => {
                Self::Only(lhs.intersection(rhs).copied().collect())
            }
            (Self::Only(keys), Self::AllExcept(excluded))
            | (Self::AllExcept(excluded), Self::Only(keys)) => {
                Self::Only(keys.difference(excluded).copied().collect())
            }
            (Self::AllExcept(lhs), Self::AllExcept(rhs)) => {
                Self::AllExcept(lhs.union(rhs).copied().collect())
            }
        }
    }

    fn union(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Only(lhs), Self::Only(rhs)) => Self::Only(lhs.union(rhs).copied().collect()),
            (Self::Only(keys), Self::AllExcept(excluded))
            | (Self::AllExcept(excluded), Self::Only(keys)) => {
                Self::AllExcept(excluded.difference(keys).copied().collect())
            }
            (Self::AllExcept(lhs), Self::AllExcept(rhs)) => {
                Self::AllExcept(lhs.intersection(rhs).copied().collect())
            }
        }
    }

    fn complement(&self) -> Self {
        match self {
            Self::Only(keys) => Self::AllExcept(keys.clone()),
            Self::AllExcept(keys) => Self::Only(keys.clone()),
        }
    }

    fn excluding(&self, excluded: &BTreeSet<Symbol>) -> Self {
        self.intersection(&Self::AllExcept(excluded.clone()))
    }

    fn into_fact(self) -> LambdaAttrKeys {
        match self {
            Self::Only(keys) => LambdaAttrKeys::Only(keys.into_iter().collect()),
            Self::AllExcept(keys) => LambdaAttrKeys::AllExcept(keys.into_iter().collect()),
        }
    }
}

#[derive(Clone, Debug)]
struct SourceRule {
    slot: u32,
    keys: KeyDomain,
}

#[derive(Clone, Debug, Default)]
struct AttrSources {
    rules: Vec<SourceRule>,
    values: Vec<(IrId, Symbol)>,
}

impl AttrSources {
    fn union(mut self, other: Self) -> Self {
        for rule in other.rules {
            if let Some(existing) = self.rules.iter_mut().find(|entry| entry.slot == rule.slot) {
                existing.keys = existing.keys.union(&rule.keys);
            } else {
                self.rules.push(rule);
            }
        }
        for value in other.values {
            if !self.values.contains(&value) {
                self.values.push(value);
            }
        }
        self
    }

    fn meet(&self, other: &Self) -> Self {
        let mut result = Self::default();
        for lhs in &self.rules {
            if let Some(rhs) = other.rules.iter().find(|rhs| rhs.slot == lhs.slot) {
                let keys = lhs.keys.intersection(&rhs.keys);
                if !keys.is_empty() {
                    result.rules.push(SourceRule {
                        slot: lhs.slot,
                        keys,
                    });
                }
            }
        }
        result.values = self
            .values
            .iter()
            .filter(|value| other.values.contains(value))
            .copied()
            .collect();
        result
    }
}

/// Returns literal binding values proven to survive a strict boundary merge.
pub(super) fn boundary_values(
    analysis: &Analysis<'_>,
    id: IrId,
    stack: &[FrameScope],
) -> Result<Vec<(IrId, Symbol)>, StrictnessAnalysisError> {
    Ok(attr_sources(analysis, id, KeyDomain::all(), stack, id, 0)?.values)
}

fn attr_sources(
    analysis: &Analysis<'_>,
    id: IrId,
    demanded: KeyDomain,
    stack: &[FrameScope],
    lambda: IrId,
    depth: usize,
) -> Result<AttrSources, StrictnessAnalysisError> {
    if demanded.is_empty() || depth >= super::frames::CHASE_BUDGET {
        return Ok(AttrSources::default());
    }
    let node = analysis.node(id)?;
    match node.data {
        IrData::Node(body) if node.kind == IrKind::ThunkAlloc => {
            attr_sources(analysis, body, demanded, stack, lambda, depth + 1)
        }
        IrData::Binary {
            op: BinOpKind::Update,
            lhs,
            rhs,
        } => {
            let rhs_may = may_keys(analysis, rhs, stack, lambda, depth + 1)?;
            let lhs_demand = demanded.intersection(&rhs_may.complement());
            let lhs = attr_sources(analysis, lhs, lhs_demand, stack, lambda, depth + 1)?;
            Ok(lhs.union(attr_sources(
                analysis,
                rhs,
                demanded,
                stack,
                lambda,
                depth + 1,
            )?))
        }
        IrData::AttrSet {
            bindings,
            recursive,
            has_dynamic,
            ..
        } if !recursive && !has_dynamic => {
            let values = analysis
                .bindings(id, bindings)?
                .iter()
                .filter_map(|binding| match binding.key {
                    IrAttrPathSegment::Static(key) if demanded.contains(key) => {
                        Some((binding.value, key))
                    }
                    IrAttrPathSegment::Static(_) | IrAttrPathSegment::Dynamic(_) => None,
                })
                .collect();
            Ok(AttrSources {
                rules: Vec::new(),
                values,
            })
        }
        IrData::Triple { second, third, .. } if node.kind == IrKind::If => {
            let then_sources =
                attr_sources(analysis, second, demanded.clone(), stack, lambda, depth + 1)?;
            let else_sources = attr_sources(analysis, third, demanded, stack, lambda, depth + 1)?;
            Ok(then_sources.meet(&else_sources))
        }
        IrData::Local { slot } if node.kind == IrKind::LocalVar => {
            attr_sources_from_variable(analysis, stack, lambda, 0, slot, demanded, depth)
        }
        IrData::Upval {
            depth: upval_depth,
            slot,
        } if node.kind == IrKind::UpvalVar => {
            attr_sources_from_variable(analysis, stack, lambda, upval_depth, slot, demanded, depth)
        }
        IrData::PrimOp { symbol, args }
            if analysis.ir.symbols.resolve(symbol) == Some(REMOVE_ATTRS) =>
        {
            let args = analysis.child_ids(id, args)?;
            let [source, exclusions] = args else {
                return Ok(AttrSources::default());
            };
            let Some(exclusions) = static_symbol_list(analysis, *exclusions)? else {
                return Ok(AttrSources::default());
            };
            attr_sources(
                analysis,
                *source,
                demanded.excluding(&exclusions),
                stack,
                lambda,
                depth + 1,
            )
        }
        _ => Ok(AttrSources::default()),
    }
}

fn attr_sources_from_variable(
    analysis: &Analysis<'_>,
    stack: &[FrameScope],
    lambda: IrId,
    upval_depth: u32,
    slot: u32,
    demanded: KeyDomain,
    chase_depth: usize,
) -> Result<AttrSources, StrictnessAnalysisError> {
    let Some(index) = stack.len().checked_sub(1 + upval_depth as usize) else {
        return Ok(AttrSources::default());
    };
    let scope = stack[index];
    if scope == FrameScope::for_lambda(lambda) {
        return Ok(AttrSources {
            rules: vec![SourceRule {
                slot,
                keys: demanded,
            }],
            values: Vec::new(),
        });
    }
    let Some(value) = resolve_slot(analysis, scope, slot)? else {
        return Ok(AttrSources::default());
    };
    attr_sources(
        analysis,
        value,
        demanded,
        &stack[..=index],
        lambda,
        chase_depth + 1,
    )
}

fn may_keys(
    analysis: &Analysis<'_>,
    id: IrId,
    stack: &[FrameScope],
    lambda: IrId,
    depth: usize,
) -> Result<KeyDomain, StrictnessAnalysisError> {
    if depth >= super::frames::CHASE_BUDGET {
        return Ok(KeyDomain::all());
    }
    let node = analysis.node(id)?;
    match node.data {
        IrData::Node(body) if node.kind == IrKind::ThunkAlloc => {
            may_keys(analysis, body, stack, lambda, depth + 1)
        }
        IrData::AttrSet {
            bindings,
            recursive,
            has_dynamic,
            ..
        } if !recursive && !has_dynamic => {
            let keys = analysis
                .bindings(id, bindings)?
                .iter()
                .filter_map(|binding| match binding.key {
                    IrAttrPathSegment::Static(key) => Some(key),
                    IrAttrPathSegment::Dynamic(_) => None,
                })
                .collect();
            Ok(KeyDomain::Only(keys))
        }
        IrData::Binary {
            op: BinOpKind::Update,
            lhs,
            rhs,
        } => Ok(
            may_keys(analysis, lhs, stack, lambda, depth + 1)?.union(&may_keys(
                analysis,
                rhs,
                stack,
                lambda,
                depth + 1,
            )?),
        ),
        IrData::Triple { second, third, .. } if node.kind == IrKind::If => Ok(may_keys(
            analysis,
            second,
            stack,
            lambda,
            depth + 1,
        )?
        .union(&may_keys(analysis, third, stack, lambda, depth + 1)?)),
        IrData::Local { slot } if node.kind == IrKind::LocalVar => {
            may_keys_from_variable(analysis, stack, lambda, 0, slot, depth)
        }
        IrData::Upval { depth: up, slot } if node.kind == IrKind::UpvalVar => {
            may_keys_from_variable(analysis, stack, lambda, up, slot, depth)
        }
        IrData::PrimOp { symbol, args }
            if analysis.ir.symbols.resolve(symbol) == Some(REMOVE_ATTRS) =>
        {
            let args = analysis.child_ids(id, args)?;
            let [source, exclusions] = args else {
                return Ok(KeyDomain::all());
            };
            let Some(exclusions) = static_symbol_list(analysis, *exclusions)? else {
                return Ok(KeyDomain::all());
            };
            Ok(may_keys(analysis, *source, stack, lambda, depth + 1)?.excluding(&exclusions))
        }
        _ => Ok(KeyDomain::all()),
    }
}

fn may_keys_from_variable(
    analysis: &Analysis<'_>,
    stack: &[FrameScope],
    lambda: IrId,
    depth: u32,
    slot: u32,
    chase_depth: usize,
) -> Result<KeyDomain, StrictnessAnalysisError> {
    let Some(index) = stack.len().checked_sub(1 + depth as usize) else {
        return Ok(KeyDomain::all());
    };
    let scope = stack[index];
    if scope == FrameScope::for_lambda(lambda) {
        return Ok(KeyDomain::all());
    }
    let Some(value) = resolve_slot(analysis, scope, slot)? else {
        return Ok(KeyDomain::all());
    };
    may_keys(analysis, value, &stack[..=index], lambda, chase_depth + 1)
}

fn static_symbol_list(
    analysis: &Analysis<'_>,
    id: IrId,
) -> Result<Option<BTreeSet<Symbol>>, StrictnessAnalysisError> {
    let node = analysis.node(id)?;
    let id = match node.data {
        IrData::Node(body) if node.kind == IrKind::ThunkAlloc => body,
        _ => id,
    };
    let node = analysis.node(id)?;
    let IrData::Children(children) = node.data else {
        return Ok(None);
    };
    if node.kind != IrKind::List {
        return Ok(None);
    }
    let mut symbols = BTreeSet::new();
    for child in analysis.child_ids(id, children)? {
        let child_node = analysis.node(*child)?;
        let child = match child_node.data {
            IrData::Node(body) if child_node.kind == IrKind::ThunkAlloc => body,
            _ => *child,
        };
        let child_node = analysis.node(child)?;
        let IrData::Symbol(symbol) = child_node.data else {
            return Ok(None);
        };
        if child_node.kind != IrKind::Str {
            return Ok(None);
        }
        symbols.insert(symbol);
    }
    Ok(Some(symbols))
}

fn variable_target_scope(stack: &[FrameScope], data: IrData) -> Option<(FrameScope, u32)> {
    let (depth, slot) = match data {
        IrData::Local { slot } => (0, slot),
        IrData::Upval { depth, slot } => (depth, slot),
        _ => return None,
    };
    let index = stack.len().checked_sub(1 + depth as usize)?;
    Some((stack[index], slot))
}
