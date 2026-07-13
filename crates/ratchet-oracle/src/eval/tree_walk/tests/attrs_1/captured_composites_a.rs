//! Force-cache tests for captured composite free variables.

use super::*;
mod part_1;
mod part_2;

fn captured_has_attr_thunk(evaluator: &mut TreeWalk, ir: &Ir, captured: Value) -> Value {
    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame.set(0, captured).expect("capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("captured hasAttr thunk allocates")
}

fn captured_has_attr_subject(
    evaluator: &TreeWalk,
    ir: &Ir,
    thunk_value: Value,
) -> Option<ForceCacheSubject> {
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("hasAttr is a node thunk");
    evaluator.force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
}

