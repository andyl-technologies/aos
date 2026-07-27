//! Exact no-callback canary for the `lib/modules.nix` name-deduplication loop.
//!
//! The canary admits only the complete lowered body used by `deepMerge`.
//! Runtime admission is narrower still: both list spines must contain already
//! evaluated strings. Any structural or value-shape mismatch resumes the
//! ordinary evaluator after the same leading demands the generic body performs.

use super::*;
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Exact primary source admitted by the production canary.
#[cfg(not(test))]
const PRIMARY_MODULES_SOURCE: &[u8] = include_bytes!("../../../../../lib/modules.nix");

/// Process-wide production activation decision.
static ENABLED: OnceLock<bool> = OnceLock::new();
static REPORT_ENABLED: OnceLock<bool> = OnceLock::new();
static BODY_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static STRUCTURAL_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static FAST_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static VALUE_DECLINES: AtomicU64 = AtomicU64::new(0);
static FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
thread_local! {
    static TEST_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TEST_ADMISSIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static TEST_EXECUTIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Source locations and lexical coordinate validated by the exact matcher.
#[derive(Clone, Copy, Debug)]
pub(super) struct DedupStringListPlan {
    remaining_id: IrId,
    remaining_span: Span,
    acc_id: IrId,
    acc_span: Span,
    acc_depth: usize,
    acc_slot: u32,
    result_id: IrId,
    result_span: Span,
}

fn enabled() -> bool {
    #[cfg(test)]
    if TEST_ENABLED.with(std::cell::Cell::get) {
        return true;
    }
    *ENABLED.get_or_init(|| {
        std::env::var_os("AOS_NIX_DEDUP_STRING_LIST_CANARY").is_some_and(|value| value == "1")
    })
}

fn report_enabled() -> bool {
    *REPORT_ENABLED.get_or_init(|| {
        std::env::var_os("AOS_NIX_DEDUP_STRING_LIST_CANARY_REPORT")
            .is_some_and(|value| value == "1")
    })
}

impl TreeWalk {
    /// Executes the exact dedup body when its static and runtime guards admit.
    pub(super) fn try_dedup_string_list_canary(
        &mut self,
        lambda: &EvalLambda,
        argument: Value,
    ) -> Option<Result<Value, TreeWalkError>> {
        if !self.dedup_string_list_runtime_enabled() {
            return None;
        }
        // The executable canary is intentionally pinned to the measured
        // `lib/modules.nix` body. The exact matcher below remains the proof;
        // this cheap filter avoids a hash lookup and first-use IR scan on
        // millions of unrelated lambda applications. Tests bypass it so the
        // matcher remains invariant under harmless node renumbering.
        #[cfg(not(test))]
        if lambda.pattern().as_u32() != 656
            || lambda.body().as_u32() != 705
            || lambda.frame().as_u32() != 55
        {
            return None;
        }
        #[cfg(not(test))]
        {
            let module = self.modules.get(lambda.module().index())?;
            let source = module.source.as_ref()?;
            let body = module.ir.arena.node(lambda.body())?;
            if !source.name.ends_with(b"/lib/modules.nix")
                || body.span.start != 13_592
                || body.span.end != 13_922
            {
                return None;
            }
        }
        if report_enabled() {
            BODY_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        }
        let key = EvalNodeRef::new(lambda.module(), lambda.body());
        let plan = if let Some(plan) = self.dedup_string_list_plans.get(&key) {
            *plan
        } else {
            let plan = self.match_dedup_string_list_body(lambda);
            self.dedup_string_list_plans.insert(key, plan);
            plan
        }?;
        if report_enabled() {
            STRUCTURAL_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
        }
        let acc = self.captured_env_value_at_depth(lambda.env(), plan.acc_depth, plan.acc_slot)?;
        match self.eval_dedup_string_list_canary(plan, acc, argument) {
            Ok(Some(value)) => {
                if report_enabled() {
                    FAST_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
                }
                Some(Ok(value))
            }
            Ok(None) => {
                if report_enabled() {
                    VALUE_DECLINES.fetch_add(1, Ordering::Relaxed);
                }
                None
            }
            Err(error) => Some(Err(error)),
        }
    }

    /// Emits diagnostic-only admission counts at demand completion.
    pub(super) fn emit_dedup_string_list_canary_report(&self) {
        if !report_enabled() {
            return;
        }
        eprintln!(
            "aos_nix_dedup_string_list_canary \
             {{\"body_attempts\":{},\"structural_admissions\":{},\
             \"fast_admissions\":{},\"value_declines\":{}}}",
            BODY_ATTEMPTS.swap(0, Ordering::Relaxed),
            STRUCTURAL_ADMISSIONS.swap(0, Ordering::Relaxed),
            FAST_ADMISSIONS.swap(0, Ordering::Relaxed),
            VALUE_DECLINES.swap(0, Ordering::Relaxed),
        );
    }

    fn dedup_string_list_runtime_enabled(&self) -> bool {
        enabled()
            && self.tier1_engine.is_none()
            && !self.options.jit_tier1_publish_enabled()
            && !self.force_cache_active
            && !self.options.memo_active()
            && !self.options.boundary_memo_active()
            && self.options.gc_mode() == EvalGcMode::Off
            && self.options.gc_stress_policy() == GcStressPolicy::disabled()
            && self.options.parallel_workers().is_none()
            && !self.options.parallel_thunk_payloads_enabled()
            && self.shared.is_none()
    }

    fn match_dedup_string_list_body(&self, lambda: &EvalLambda) -> Option<DedupStringListPlan> {
        macro_rules! required {
            ($name:literal, $value:expr) => {
                match $value {
                    Some(value) => value,
                    None => {
                        report_match_failure($name);
                        return None;
                    }
                }
            };
        }
        #[cfg(not(test))]
        {
            let module = self.modules.get(lambda.module().index())?;
            let source = module.source.as_ref()?;
            if source.bytes.as_slice() != PRIMARY_MODULES_SOURCE {
                report_match_failure("source");
                return None;
            }
        }
        let ir = self.module_ir(lambda.module()).ok()?;
        let frame = lambda.frame();
        if ir.frames.get(frame.index())?.slot_count != 1 {
            report_match_failure("lambda frame");
            return None;
        }
        required!("formal", match_formal(ir, lambda.pattern()));
        let (condition, empty_result, nonempty) =
            required!("outer if", match_triple(ir, lambda.body(), IrKind::If));
        let (remaining_id, empty_list) =
            required!("empty eq", match_binary(ir, condition, BinOpKind::Eq));
        required!("remaining local", match_local(ir, remaining_id, 0));
        required!("empty list", match_list(ir, empty_list, &[]));
        let (acc_depth, acc_slot) = required!("empty acc", match_upval(ir, empty_result));
        if acc_depth != 1 {
            report_match_failure("acc depth");
            return None;
        }

        let (bindings, inner_if, let_frame) = required!("inner let", match_let(ir, nonempty));
        if bindings.len != 2 || ir.frames.get(let_frame?.index())?.slot_count != 2 {
            report_match_failure("inner bindings");
            return None;
        }
        let start = usize::try_from(bindings.start).ok()?;
        let end = start.checked_add(usize::try_from(bindings.len).ok()?)?;
        let inner_bindings = ir.bindings.get(start..end)?;
        let h_binding = required!(
            "h binding",
            inner_bindings.iter().find(|binding| {
                match_thunk(ir, binding.value)
                    .and_then(|body| primop_args(ir, &self.symbols, body, b"elemAt"))
                    .is_some()
            })
        );
        let t_binding = required!(
            "t binding",
            inner_bindings.iter().find(|binding| {
                match_thunk(ir, binding.value)
                    .and_then(|body| primop_args(ir, &self.symbols, body, b"genList"))
                    .is_some()
            })
        );
        let h_value = required!("h thunk", match_thunk(ir, h_binding.value));
        required!(
            "h elemAt",
            match_primop(
                ir,
                &self.symbols,
                h_value,
                b"elemAt",
                &[NodeMatch::UpvalSlot(0), NodeMatch::Int(0)]
            )
        );
        let t_value = required!("t thunk", match_thunk(ir, t_binding.value));
        let t_args = required!(
            "t genList",
            primop_args(ir, &self.symbols, t_value, b"genList")
        );
        if t_args.len() != 2 {
            report_match_failure("genList arity");
            return None;
        }
        required!(
            "genList lambda",
            match_genlist_lambda(ir, &self.symbols, t_args[0])
        );
        let (length, one) = required!("length sub", match_binary(ir, t_args[1], BinOpKind::Sub));
        required!(
            "length primop",
            match_primop(
                ir,
                &self.symbols,
                length,
                b"length",
                &[NodeMatch::UpvalSlot(0)]
            )
        );
        required!("sub one", match_int(ir, one, 1));

        let (seen, duplicate, unique) =
            required!("inner if", match_triple(ir, inner_if, IrKind::If));
        let any_args = required!("any", primop_args(ir, &self.symbols, seen, b"any"));
        if any_args.len() != 2 {
            report_match_failure("any arity");
            return None;
        }
        required!(
            "any lambda",
            match_any_lambda(ir, &self.symbols, any_args[0])
        );
        required!("any acc", match_upval_slot(ir, any_args[1], 0));
        let duplicate_target = required!(
            "duplicate branch",
            match_recursive_branch(ir, duplicate, false)
        );
        let unique_target = required!("unique branch", match_recursive_branch(ir, unique, true));
        if duplicate_target.0 != 3 || duplicate_target != unique_target {
            report_match_failure("recursive target mismatch");
            return None;
        }

        let remaining_node = ir.arena.node(remaining_id)?;
        let acc_node = ir.arena.node(empty_result)?;
        let result_node = ir.arena.node(unique)?;
        note_test_admission();
        Some(DedupStringListPlan {
            remaining_id,
            remaining_span: remaining_node.span,
            acc_id: empty_result,
            acc_span: acc_node.span,
            acc_depth: usize::try_from(acc_depth).ok()?.checked_sub(1)?,
            acc_slot,
            result_id: unique,
            result_span: result_node.span,
        })
    }

    fn eval_dedup_string_list_canary(
        &mut self,
        plan: DedupStringListPlan,
        acc: Value,
        remaining: Value,
    ) -> Result<Option<Value>, TreeWalkError> {
        let remaining =
            self.force_node_result(plan.remaining_id, plan.remaining_span, remaining)?;
        let remaining =
            self.force_demanded_value(plan.remaining_id, plan.remaining_span, remaining)?;
        if remaining.tag() != ValueTag::List {
            return Ok(None);
        }
        let remaining_values = {
            let list = self.heap.get_list(remaining).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: plan.remaining_id,
                        source,
                    },
                    plan.remaining_span,
                )
            })?;
            Self::clone_list_elements(plan.remaining_id, plan.remaining_span, list)?
        };
        if remaining_values.is_empty() {
            return Ok(Some(acc));
        }
        // The generic body recursively applies `dedup`, `genList`, `elemAt`,
        // `any`, and the equality predicate. The canary does not reproduce
        // those transient frames, so admit only when a deliberately loose
        // upper bound proves that none of their depth checks could fail.
        let logical_depth_headroom = remaining_values.len().saturating_mul(8).saturating_add(16);
        if self.call_depth.saturating_add(logical_depth_headroom) > self.options.max_call_depth() {
            return Ok(None);
        }
        if remaining_values
            .iter()
            .any(|value| value.tag() != ValueTag::String)
        {
            return Ok(None);
        }

        let acc = self.force_node_result(plan.acc_id, plan.acc_span, acc)?;
        let acc = self.force_demanded_value(plan.acc_id, plan.acc_span, acc)?;
        if acc.tag() != ValueTag::List {
            return Ok(None);
        }
        let acc_values = {
            let list = self.heap.get_list(acc).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: plan.acc_id,
                        source,
                    },
                    plan.acc_span,
                )
            })?;
            Self::clone_list_elements(plan.acc_id, plan.acc_span, list)?
        };
        if acc_values
            .iter()
            .any(|value| value.tag() != ValueTag::String)
        {
            return Ok(None);
        }
        note_test_execution();

        let mut output = acc_values;
        output.try_reserve(remaining_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: plan.result_id,
                    len: output.len().saturating_add(remaining_values.len()),
                },
                plan.result_span,
            )
        })?;
        let initial_len = output.len();
        for candidate in remaining_values {
            let duplicate = output.iter().copied().any(|seen| {
                self.heap
                    .get_string(seen)
                    .ok()
                    .zip(self.heap.get_string(candidate).ok())
                    .is_some_and(|(left, right)| left.bytes() == right.bytes())
            });
            if !duplicate {
                output.push(candidate);
            }
        }
        if output.len() == initial_len {
            return Ok(Some(acc));
        }
        self.alloc_tree_walk_list(plan.result_id, plan.result_span, NixList::new(output))
            .map(Some)
    }
}

fn report_match_failure(stage: &'static str) {
    if report_enabled() && !FAILURE_REPORTED.swap(true, Ordering::Relaxed) {
        eprintln!("aos_nix_dedup_string_list_canary_match_failure {{\"stage\":{stage:?}}}");
    }
}

#[derive(Clone, Copy)]
enum NodeMatch {
    Int(i64),
    UpvalSlot(u32),
}

fn node(ir: &Ir, id: IrId, kind: IrKind) -> Option<&IrNode> {
    let node = ir.arena.node(id)?;
    (node.kind == kind && node.effect.is_speculable()).then_some(node)
}

fn match_formal(ir: &Ir, id: IrId) -> Option<()> {
    let node = node(ir, id, IrKind::Formal)?;
    matches!(node.data, IrData::Formal { default: None, .. }).then_some(())
}

fn match_int(ir: &Ir, id: IrId, expected: i64) -> Option<()> {
    matches!(node(ir, id, IrKind::Int)?.data, IrData::Int(value) if value == expected).then_some(())
}

fn match_local(ir: &Ir, id: IrId, expected: u32) -> Option<()> {
    matches!(node(ir, id, IrKind::LocalVar)?.data, IrData::Local { slot } if slot == expected)
        .then_some(())
}

fn match_upval(ir: &Ir, id: IrId) -> Option<(u32, u32)> {
    let IrData::Upval { depth, slot } = node(ir, id, IrKind::UpvalVar)?.data else {
        return None;
    };
    Some((depth, slot))
}

fn match_upval_slot(ir: &Ir, id: IrId, slot: u32) -> Option<()> {
    (match_upval(ir, id)?.1 == slot).then_some(())
}

fn match_binary(ir: &Ir, id: IrId, expected: BinOpKind) -> Option<(IrId, IrId)> {
    let IrData::Binary { op, lhs, rhs } = node(ir, id, IrKind::BinOp)?.data else {
        return None;
    };
    (op == expected).then_some((lhs, rhs))
}

fn match_triple(ir: &Ir, id: IrId, kind: IrKind) -> Option<(IrId, IrId, IrId)> {
    let IrData::Triple {
        first,
        second,
        third,
    } = node(ir, id, kind)?.data
    else {
        return None;
    };
    Some((first, second, third))
}

fn match_let(ir: &Ir, id: IrId) -> Option<(crate::compile::IrBindingSlice, IrId, Option<FrameId>)> {
    let IrData::Let {
        bindings,
        body,
        frame,
    } = node(ir, id, IrKind::Let)?.data
    else {
        return None;
    };
    Some((bindings, body, frame))
}

fn match_thunk(ir: &Ir, id: IrId) -> Option<IrId> {
    let IrData::Node(body) = node(ir, id, IrKind::ThunkAlloc)?.data else {
        return None;
    };
    Some(body)
}

fn match_list(ir: &Ir, id: IrId, expected: &[NodeMatch]) -> Option<()> {
    let IrData::Children(children) = node(ir, id, IrKind::List)?.data else {
        return None;
    };
    let children = ir.arena.child_slice(children)?;
    if children.len() != expected.len() {
        return None;
    }
    children
        .iter()
        .copied()
        .zip(expected.iter().copied())
        .try_for_each(|(child, expected)| match_node(ir, child, expected))
}

fn match_node(ir: &Ir, id: IrId, expected: NodeMatch) -> Option<()> {
    match expected {
        NodeMatch::Int(value) => match_int(ir, id, value),
        NodeMatch::UpvalSlot(slot) => match_upval_slot(ir, id, slot),
    }
}

fn primop_args<'a>(
    ir: &'a Ir,
    symbols: &SymbolTable,
    id: IrId,
    expected: &[u8],
) -> Option<&'a [IrId]> {
    let IrData::PrimOp { symbol, args } = node(ir, id, IrKind::PrimOp)?.data else {
        return None;
    };
    (symbols.resolve(symbol)? == expected)
        .then(|| ir.arena.child_slice(args))
        .flatten()
}

fn match_primop(
    ir: &Ir,
    symbols: &SymbolTable,
    id: IrId,
    name: &[u8],
    expected: &[NodeMatch],
) -> Option<()> {
    let args = primop_args(ir, symbols, id, name)?;
    if args.len() != expected.len() {
        return None;
    }
    args.iter()
        .copied()
        .zip(expected.iter().copied())
        .try_for_each(|(argument, expected)| match_node(ir, argument, expected))
}

fn match_genlist_lambda(ir: &Ir, symbols: &SymbolTable, id: IrId) -> Option<()> {
    let IrData::Lambda {
        pattern,
        body,
        frame,
    } = node(ir, id, IrKind::Lambda)?.data
    else {
        return None;
    };
    match_formal(ir, pattern)?;
    if ir.frames.get(frame?.index())?.slot_count != 1 {
        return None;
    }
    let args = primop_args(ir, symbols, body, b"elemAt")?;
    if args.len() != 2 {
        return None;
    }
    match_upval_slot(ir, args[0], 0)?;
    let (index, one) = match_binary(ir, args[1], BinOpKind::Add)?;
    match_local(ir, index, 0)?;
    match_int(ir, one, 1)
}

fn match_any_lambda(ir: &Ir, _symbols: &SymbolTable, id: IrId) -> Option<()> {
    let IrData::Lambda {
        pattern,
        body,
        frame,
    } = node(ir, id, IrKind::Lambda)?.data
    else {
        return None;
    };
    match_formal(ir, pattern)?;
    if ir.frames.get(frame?.index())?.slot_count != 1 {
        return None;
    }
    let (left, right) = match_binary(ir, body, BinOpKind::Eq)?;
    match_local(ir, left, 0)?;
    match_upval_slot(ir, right, 0)
}

fn match_recursive_branch(ir: &Ir, id: IrId, append: bool) -> Option<(u32, u32)> {
    let IrData::Pair {
        first: partial,
        second: t,
    } = node(ir, id, IrKind::Apply)?.data
    else {
        return None;
    };
    match_local(ir, match_thunk(ir, t)?, 1)?;
    let IrData::Pair {
        first: dedup,
        second: acc,
    } = node(ir, partial, IrKind::Apply)?.data
    else {
        return None;
    };
    let target = match_upval(ir, dedup)?;
    let acc = match_thunk(ir, acc)?;
    if !append {
        match_upval_slot(ir, acc, 0)?;
        return Some(target);
    }
    let (left, right) = match_binary(ir, acc, BinOpKind::Concat)?;
    match_upval_slot(ir, left, 0)?;
    let IrData::Children(children) = node(ir, right, IrKind::List)?.data else {
        return None;
    };
    let [element] = ir.arena.child_slice(children)? else {
        return None;
    };
    match_local(ir, match_thunk(ir, *element)?, 0)?;
    Some(target)
}

#[cfg(test)]
fn note_test_admission() {
    TEST_ADMISSIONS.with(|admissions| admissions.set(admissions.get().saturating_add(1)));
}

#[cfg(not(test))]
const fn note_test_admission() {}

#[cfg(test)]
fn note_test_execution() {
    TEST_EXECUTIONS.with(|executions| executions.set(executions.get().saturating_add(1)));
}

#[cfg(not(test))]
const fn note_test_execution() {}

/// Runs one test closure and reports static admissions and direct executions.
#[cfg(test)]
pub(super) fn with_test_enabled<T>(f: impl FnOnce() -> T) -> (T, u64, u64) {
    TEST_ENABLED.with(|enabled| {
        TEST_ADMISSIONS.with(|admissions| {
            TEST_EXECUTIONS.with(|executions| {
                let saved_enabled = enabled.replace(true);
                let saved_admissions = admissions.replace(0);
                let saved_executions = executions.replace(0);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
                let observed_admissions = admissions.replace(saved_admissions);
                let observed_executions = executions.replace(saved_executions);
                enabled.set(saved_enabled);
                match result {
                    Ok(value) => (value, observed_admissions, observed_executions),
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            })
        })
    })
}

#[cfg(test)]
mod primary_match_tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::syntax::parse_str;

    #[test]
    fn matches_the_complete_modules_source_ir() {
        let source = include_str!("../../../../../lib/modules.nix");
        let ir = aos_nix_dialect::nix_lower(
            resolve_ast(parse_str(source).expect("modules source parses"))
                .expect("modules source resolves"),
        )
        .expect("modules source lowers");
        let evaluator = TreeWalk::with_options_and_source(
            &ir,
            TreeWalkOptions::default(),
            b"/source/lib/modules.nix",
            source.as_bytes(),
        );
        let lambda = EvalLambda::new(
            IrId::new(656),
            IrId::new(705),
            FrameId::new(55),
            EvalEnv::default(),
        );
        assert!(
            evaluator.match_dedup_string_list_body(&lambda).is_some(),
            "the source-pinned primary body must match"
        );
    }
}
