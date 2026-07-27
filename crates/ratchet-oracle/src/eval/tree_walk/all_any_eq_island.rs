//! Default-off fused `builtins.any (element: element == captured)` experiment.
//!
//! Admission recognizes one exact lowered lambda and lexical-capture shape.
//! The fused loop preserves the lambda body's left-to-right operand forcing and
//! delegates equality itself to the ordinary direct-equality implementation.

use super::*;
use std::sync::OnceLock;

/// Process-wide production activation decision.
static ENABLED: OnceLock<bool> = OnceLock::new();

#[cfg(test)]
thread_local! {
    /// Per-test-thread override that avoids mutating the process environment.
    static TEST_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Admissions observed by the current test thread.
    static TEST_ADMISSIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Prevalidated metadata and the captured equality candidate.
pub(super) struct AnyEqualityIsland {
    module: EvalModuleId,
    equality_id: IrId,
    equality_node: IrNode,
    element_id: IrId,
    element_span: Span,
    candidate_id: IrId,
    candidate_span: Span,
    candidate: Value,
}

/// Returns whether the experimental island is explicitly enabled.
fn enabled() -> bool {
    #[cfg(test)]
    if TEST_ENABLED.with(std::cell::Cell::get) {
        return true;
    }
    *ENABLED.get_or_init(|| {
        std::env::var_os("AOS_NIX_ALL_ANY_EQ_ISLAND").is_some_and(|value| value == "1")
    })
}

impl TreeWalk {
    /// Recognizes the exact any-equality lambda without changing evaluator state.
    pub(super) fn prepare_any_equality_island(
        &self,
        op: AllAnyOp,
        predicate: Value,
        has_elements: bool,
    ) -> Option<AnyEqualityIsland> {
        if !enabled()
            || op != AllAnyOp::Any
            || !has_elements
            || predicate.tag() != ValueTag::Lambda
            || self.tier1_engine.is_some()
            || self.options.jit_tier1_publish_enabled()
            || self.force_cache_active
            || self.options.memo_active()
            || self.options.boundary_memo_active()
            || self.options.gc_mode() != EvalGcMode::Off
            || self.options.gc_stress_policy() != GcStressPolicy::disabled()
            || self.options.parallel_workers().is_some()
            || self.options.parallel_thunk_payloads_enabled()
            || self.shared.is_some()
        {
            return None;
        }
        let lambda = self.heap.clone_lambda(predicate).ok()?;
        if !lambda.with_scope_env().is_empty() || !lambda.scoped_global_env().is_empty() {
            return None;
        }
        let ir = self.module_ir(lambda.module()).ok()?;
        if ir.frames.get(lambda.frame().index())?.slot_count != 1 {
            return None;
        }
        let pattern = ir.arena.node(lambda.pattern())?;
        if !matches!(
            pattern.data,
            IrData::Formal {
                name: _,
                default: None
            }
        ) || pattern.kind != IrKind::Formal
        {
            return None;
        }
        let equality_node = *ir.arena.node(lambda.body())?;
        let IrData::Binary {
            op: BinOpKind::Eq,
            lhs,
            rhs,
        } = equality_node.data
        else {
            return None;
        };
        if equality_node.kind != IrKind::BinOp {
            return None;
        }
        let element_node = *ir.arena.node(lhs)?;
        if !matches!(element_node.data, IrData::Local { slot: 0 })
            || element_node.kind != IrKind::LocalVar
        {
            return None;
        }
        let candidate_node = *ir.arena.node(rhs)?;
        let IrData::Upval { depth, slot: 0 } = candidate_node.data else {
            return None;
        };
        if candidate_node.kind != IrKind::UpvalVar {
            return None;
        }
        // The future element call frame is absent from the captured
        // environment, so remove exactly that frame from the body coordinate.
        let candidate_depth = usize::try_from(depth).ok()?.checked_sub(1)?;
        let candidate = self.captured_env_value_at_depth(lambda.env(), candidate_depth, 0)?;
        note_test_admission();
        Some(AnyEqualityIsland {
            module: lambda.module(),
            equality_id: lambda.body(),
            equality_node,
            element_id: lhs,
            element_span: element_node.span,
            candidate_id: rhs,
            candidate_span: candidate_node.span,
            candidate,
        })
    }

    /// Executes an admitted island with ordinary call and equality semantics.
    pub(super) fn eval_any_equality_island(
        &mut self,
        id: IrId,
        span: Span,
        island: AnyEqualityIsland,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        for element in elements {
            if self.eval_any_equality_island_element(id, span, &island, element)? {
                return Ok(Value::bool(true));
            }
        }
        Ok(Value::bool(false))
    }

    /// Applies one exact predicate through the established recursive helpers.
    fn eval_any_equality_island_element(
        &mut self,
        id: IrId,
        span: Span,
        island: &AnyEqualityIsland,
        element: Value,
    ) -> Result<bool, TreeWalkError> {
        self.increment_function_calls();
        let saved_module = self.current_module;
        self.current_module = island.module;
        if let Err(error) = self.enter_call(id, span) {
            self.current_module = saved_module;
            return Err(error);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.force_and_compare_any_equality_operands(island, element)
        }));
        let result = match result {
            Ok(result) => Ok(result.map_err(|error| self.error_with_current_source(error))),
            Err(payload) => Err(payload),
        };
        self.leave_call();
        self.current_module = saved_module;
        match result {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    /// Forces exact equality operands in generic Local/Upval evaluation order.
    fn force_and_compare_any_equality_operands(
        &mut self,
        island: &AnyEqualityIsland,
        element: Value,
    ) -> Result<bool, TreeWalkError> {
        let element = self.force_node_result(island.element_id, island.element_span, element)?;
        let element = self.force_demanded_value(island.element_id, island.element_span, element)?;
        let candidate =
            self.force_node_result(island.candidate_id, island.candidate_span, island.candidate)?;
        let candidate =
            self.force_demanded_value(island.candidate_id, island.candidate_span, candidate)?;
        self.values_equal(
            island.equality_id,
            &island.equality_node,
            element,
            candidate,
            EqualityContext::Direct,
        )
    }
}

#[cfg(test)]
fn note_test_admission() {
    TEST_ADMISSIONS.with(|admissions| admissions.set(admissions.get().saturating_add(1)));
}

#[cfg(not(test))]
const fn note_test_admission() {}

/// Runs one test closure with the island enabled and returns its admission count.
#[cfg(test)]
pub(super) fn with_test_enabled<T>(f: impl FnOnce() -> T) -> (T, u64) {
    TEST_ENABLED.with(|enabled| {
        TEST_ADMISSIONS.with(|admissions| {
            let saved_enabled = enabled.replace(true);
            let saved_admissions = admissions.replace(0);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            let observed = admissions.replace(saved_admissions);
            enabled.set(saved_enabled);
            match result {
                Ok(value) => (value, observed),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        })
    })
}
