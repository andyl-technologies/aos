//! Evaluator-owned ordinary thunk force-lease lifecycle tests.

use super::*;
#[cfg(feature = "collection_poll_probe")]
use crate::eval::heap::EvalRootSource;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn fixture(source: &str) -> (TreeWalk, IrId, Span, Value) {
    let ir = lower(source);
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let thunk = evaluator
        .alloc_tree_walk_thunk(id, span, EvalThunk::new(id))
        .expect("ordinary Node thunk allocates");
    (evaluator, id, span, thunk)
}

fn begin(evaluator: &mut TreeWalk, id: IrId, span: Span, thunk: Value) -> ForceLeaseToken {
    match evaluator
        .begin_force_lease(id, span, thunk)
        .expect("force lease begins")
    {
        BeginForceLease::Claimed(token) => token,
        BeginForceLease::AlreadyForced(_) => panic!("fresh thunk is not forced"),
        BeginForceLease::Declined => panic!("ordinary Node thunk is admitted"),
    }
}

#[cfg(feature = "collection_poll_probe")]
fn enable_active_node_detachment(evaluator: &mut TreeWalk) {
    evaluator.active_node_work_detachment_test_enabled = true;
}

#[test]
fn force_lease_success_publishes_and_replays() {
    let (mut evaluator, id, span, thunk) = fixture("null");
    let token = begin(&mut evaluator, id, span, thunk);

    let value = evaluator
        .run_force_lease_with(id, span, token, |_| Ok(Value::int(42)))
        .expect("lease publishes");

    assert!(value.raw_eq(Value::int(42)));
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_force_roots.is_empty());
    let replay = evaluator
        .force_value(id, span, thunk)
        .expect("published thunk replays");
    assert!(replay.raw_eq(value));
}

#[test]
fn force_lease_body_error_aborts_and_can_retry() {
    let (mut evaluator, id, span, thunk) = fixture("null");
    let token = begin(&mut evaluator, id, span, thunk);
    let error = TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, span);

    let returned = evaluator
        .run_force_lease_with(id, span, token, |_| Err(error))
        .expect_err("body error propagates");
    assert!(matches!(
        returned.kind(),
        TreeWalkErrorKind::InvalidNodeId { .. }
    ));
    assert_eq!(
        evaluator
            .heap
            .get_thunk(thunk)
            .expect("thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );

    let retry = begin(&mut evaluator, id, span, thunk);
    evaluator
        .abort_force_lease(id, span, retry)
        .expect("retry claim aborts");
}

#[test]
fn force_lease_stale_same_depth_token_is_rejected() {
    let (mut evaluator, id, span, first) = fixture("null");
    let second = evaluator
        .alloc_tree_walk_thunk(id, span, EvalThunk::new(id))
        .expect("second thunk allocates");
    let stale = begin(&mut evaluator, id, span, first);
    evaluator
        .abort_force_lease(id, span, stale)
        .expect("first lease aborts");
    let current = begin(&mut evaluator, id, span, second);

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = evaluator.abort_force_lease(id, span, stale);
    }));
    assert!(panic.is_err(), "stale generation must panic");
    evaluator
        .abort_force_lease(id, span, current)
        .expect("current lease remains active");
}

#[test]
fn force_lease_generation_exhaustion_precedes_blackhole_mutation() {
    let (mut evaluator, id, span, thunk) = fixture("null");
    evaluator.next_force_lease_generation = u64::MAX;

    let error = evaluator
        .begin_force_lease(id, span, thunk)
        .expect_err("generation exhaustion is reported");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::ForceLeaseGenerationExhausted { .. }
    ));
    assert_eq!(
        evaluator
            .heap
            .get_thunk(thunk)
            .expect("thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_force_roots.is_empty());
}

#[test]
fn force_lease_admits_ordinary_apply_for_explicit_machine_updates() {
    let (mut evaluator, id, span, _) = fixture("null");
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, Value::int(1), id, Value::int(2))
        .expect("Apply thunk allocates");

    let BeginForceLease::Claimed(token) = evaluator
        .begin_force_lease(id, span, apply)
        .expect("ordinary Apply obtains a detached update lease")
    else {
        panic!("ordinary Apply must be admitted");
    };
    evaluator
        .abort_force_lease(id, span, token)
        .expect("Apply update lease aborts");
    assert_eq!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_force_roots.is_empty());
}

#[cfg(feature = "candidate_c_value")]
#[test]
fn force_lease_declines_typed_apply_head_before_claiming_or_taking_work() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, Value::int(1), id, Value::int(2))
        .expect("typed Apply head allocates");
    let (heads_before, live_before, _, _, _) = evaluator.heap.typed_thunk_head_counts();

    assert!(heads_before > 0, "Candidate-C uses a typed Apply head");
    assert!(live_before > 0, "typed suspended work is live");
    assert!(matches!(
        evaluator
            .begin_force_lease(id, span, apply)
            .expect("typed head is a clean decline"),
        BeginForceLease::Declined
    ));
    assert_eq!(
        evaluator.heap.typed_thunk_state_if_any(apply),
        Some(ThunkState::Suspended)
    );
    let (heads_after, live_after, _, _, _) = evaluator.heap.typed_thunk_head_counts();
    assert_eq!(heads_after, heads_before);
    assert_eq!(
        live_after, live_before,
        "decline must not take or release detached work"
    );
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_force_roots.is_empty());
}

#[test]
fn force_leases_nest_strictly() {
    let (mut evaluator, id, span, outer) = fixture("null");
    let inner = evaluator
        .alloc_tree_walk_thunk(id, span, EvalThunk::new(id))
        .expect("inner thunk allocates");
    let outer_token = begin(&mut evaluator, id, span, outer);
    let inner_token = begin(&mut evaluator, id, span, inner);

    evaluator
        .finish_force_lease(id, span, inner_token, Value::int(2))
        .expect("inner finishes");
    evaluator
        .finish_force_lease(id, span, outer_token, Value::int(1))
        .expect("outer finishes");

    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_force_roots.is_empty());
}

#[test]
fn force_lease_injected_panic_aborts_before_unwind_resumes() {
    let (mut evaluator, id, span, thunk) = fixture("null");
    let token = begin(&mut evaluator, id, span, thunk);

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = evaluator
            .run_force_lease_with(id, span, token, |_| panic!("injected force body panic"));
    }));

    assert!(panic.is_err());
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_force_roots.is_empty());
    assert_eq!(
        evaluator
            .heap
            .get_thunk(thunk)
            .expect("thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
}

#[test]
fn force_lease_preserves_displaced_older_roots() {
    let (mut evaluator, id, span, thunk) = fixture("null");
    let displaced = Value::int(7);
    evaluator
        .push_active_force_root(id, span, displaced)
        .expect("older force root pushes");
    let token = begin(&mut evaluator, id, span, thunk);

    evaluator
        .finish_force_lease(id, span, token, Value::int(8))
        .expect("lease finishes above older root");

    assert_eq!(evaluator.active_force_roots.len(), 1);
    assert!(evaluator.active_force_roots[0].raw_eq(displaced));
    assert!(evaluator.pop_active_force_root().raw_eq(displaced));
}

#[cfg(feature = "collection_poll_probe")]
#[test]
fn detached_node_force_success_releases_work_and_preserves_publication_identity() {
    let (mut evaluator, id, span, thunk) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let token = begin(&mut evaluator, id, span, thunk);

    assert_eq!(evaluator.active_node_work_leases.len(), 1);
    assert!(matches!(
        evaluator
            .heap
            .get_thunk(thunk)
            .expect("source resolves")
            .kind(),
        EvalThunkKind::Released
    ));
    let value = evaluator
        .run_force_lease_with(id, span, token, |_| Ok(Value::int(17)))
        .expect("detached force publishes");

    assert!(value.raw_eq(Value::int(17)));
    assert!(evaluator.active_node_work_leases.is_empty());
    assert_eq!(
        evaluator
            .heap
            .get_thunk(thunk)
            .expect("source resolves")
            .cell()
            .state(),
        Ok(ThunkState::Forced)
    );
    assert!(
        evaluator
            .force_value(id, span, thunk)
            .expect("same identity replays")
            .raw_eq(value)
    );
}

#[cfg(feature = "collection_poll_probe")]
#[test]
fn detached_node_force_error_restores_exact_suspended_work_before_retry() {
    let (mut evaluator, id, span, thunk) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let token = begin(&mut evaluator, id, span, thunk);
    let error = TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, span);

    let returned = evaluator
        .run_force_lease_with(id, span, token, |_| Err(error))
        .expect_err("body error propagates");

    assert!(matches!(
        returned.kind(),
        TreeWalkErrorKind::InvalidNodeId { .. }
    ));
    let restored = evaluator.heap.get_thunk(thunk).expect("source restores");
    assert_eq!(restored.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(restored.body(), Some(id));
    assert!(evaluator.active_node_work_leases.is_empty());
    let retry = begin(&mut evaluator, id, span, thunk);
    evaluator
        .abort_force_lease(id, span, retry)
        .expect("restored work claims again");
}

#[cfg(feature = "collection_poll_probe")]
#[test]
fn detached_node_force_panic_restores_work_before_unwind() {
    let (mut evaluator, id, span, thunk) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let token = begin(&mut evaluator, id, span, thunk);

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = evaluator.run_force_lease_with(id, span, token, |_| panic!("detached body panic"));
    }));

    assert!(panic.is_err());
    let restored = evaluator.heap.get_thunk(thunk).expect("source restores");
    assert_eq!(restored.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(restored.body(), Some(id));
    assert!(evaluator.active_node_work_leases.is_empty());
}

#[cfg(feature = "collection_poll_probe")]
#[test]
fn detached_node_recursive_force_observes_blackhole_and_restores_after_error() {
    let (mut evaluator, id, span, thunk) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let token = begin(&mut evaluator, id, span, thunk);

    let error = evaluator
        .run_force_lease_with(id, span, token, |eval| eval.force_value(id, span, thunk))
        .expect_err("recursive force rejects the active blackhole");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Force {
            source: ForceError::InfiniteRecursion,
            ..
        }
    ));
    let restored = evaluator.heap.get_thunk(thunk).expect("source restores");
    assert_eq!(restored.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(restored.body(), Some(id));
}

#[cfg(feature = "collection_poll_probe")]
#[test]
fn detached_node_capture_root_is_writable_and_restored_in_destination_domain() {
    let (mut evaluator, id, span, _) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let original = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(id))
        .expect("original capture allocates");
    let replacement = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(id))
        .expect("replacement capture allocates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, original).expect("capture stores");
    let env = EvalEnv::capture(&[Arc::clone(&frame)]).expect("environment captures");
    let owner = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, id, env))
        .expect("capturing Node allocates");
    let token = begin(&mut evaluator, id, span, owner);
    let roots = evaluator.mutator_root_set().expect("roots enumerate");
    let source = roots
        .roots()
        .iter()
        .find_map(|root| {
            matches!(root.source(), EvalRootSource::DetachedNodeThunkWork { .. })
                .then(|| root.source().clone())
        })
        .expect("detached capture is rooted");

    evaluator
        .write_safepoint_root_writeback_value(&source, replacement, &mut [], &mut [])
        .expect("detached capture writes back");
    evaluator
        .abort_force_lease(id, span, token)
        .expect("detached work restores");

    assert!(
        frame.get(0).expect("capture reads").raw_eq(replacement),
        "restored suspended work must retain the relocated capture"
    );
}

#[cfg(all(feature = "collection_poll_probe", feature = "evacuation_plan_probe"))]
#[test]
fn detached_node_blackhole_hard_pin_island_excludes_detached_descendants() {
    let (mut evaluator, id, span, _) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let captured = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"detached descendant".to_vec()))
        .expect("captured string allocates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, captured).expect("capture stores");
    let env = EvalEnv::capture(&[frame]).expect("environment captures");
    let owner = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, id, env))
        .expect("capturing Node allocates");
    let token = begin(&mut evaluator, id, span, owner);
    let roots = evaluator.mutator_root_set().expect("roots enumerate");

    let plan = evaluator
        .heap
        .evacuation_plan(&roots)
        .expect("plan accepts detached work roots");
    let report = plan.to_string();

    assert!(report.contains("\"hard_seed_objects\":1"));
    assert!(report.contains("\"transitive_retained_objects\":0"));
    assert!(report.contains("\"retained_objects\":1"));
    evaluator
        .abort_force_lease(id, span, token)
        .expect("work restores after census");
}

#[cfg(feature = "collection_poll_probe")]
#[test]
fn detached_inline_capture_tail_transfers_to_writable_lease_roots() {
    let (mut evaluator, id, span, _) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let original = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"original tail".to_vec()))
        .expect("original tail value allocates");
    let replacement = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"replacement tail".to_vec()))
        .expect("replacement tail value allocates");
    let site = EvalNodeRef::new(EvalModuleId::ROOT, id);
    let mut capture = EvalFlatCaptureBuffer::new(site, 1);
    capture.push(original).expect("tail capture appends");
    let (owner, _) = evaluator
        .heap
        .alloc_thunk_with_flat_capture(EvalThunk::new(id), Some(capture.finish()))
        .expect("tail-capturing thunk allocates");
    let token = begin(&mut evaluator, id, span, owner);

    let roots = evaluator.mutator_root_set().expect("lease roots enumerate");
    let source = roots
        .roots()
        .iter()
        .find(|root| {
            matches!(root.source(), EvalRootSource::DetachedNodeThunkWork { .. })
                && root.value().raw_eq(original)
        })
        .map(|root| root.source().clone())
        .expect("source-resident tail value is a lease root");
    evaluator
        .write_safepoint_root_writeback_value(&source, replacement, &mut [], &mut [])
        .expect("tail lease root writes in place");
    assert!(
        evaluator
            .heap
            .flat_closure_capture_values(owner)
            .expect("owner tail resolves")
            .expect("owner has a tail")[0]
            .raw_eq(replacement)
    );

    evaluator
        .abort_force_lease(id, span, token)
        .expect("tail-owning work restores");
    let restored = evaluator.heap.get_thunk(owner).expect("owner restores");
    assert_eq!(restored.cell().state(), Ok(ThunkState::Suspended));
    assert!(matches!(restored.kind(), EvalThunkKind::Node { .. }));
    assert!(
        evaluator
            .heap
            .flat_closure_capture_values(owner)
            .expect("restored tail resolves")
            .expect("restored owner has a tail")[0]
            .raw_eq(replacement),
        "rollback preserves collector-rewritten tail values"
    );
}

#[cfg(all(feature = "collection_poll_probe", feature = "evacuation_plan_probe"))]
#[test]
fn detached_inline_capture_tail_is_not_a_hard_seed_edge() {
    let (mut evaluator, id, span, _) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let captured = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"leased tail descendant".to_vec()))
        .expect("tail descendant allocates");
    let mut capture = EvalFlatCaptureBuffer::new(EvalNodeRef::new(EvalModuleId::ROOT, id), 1);
    capture.push(captured).expect("tail capture appends");
    let (owner, _) = evaluator
        .heap
        .alloc_thunk_with_flat_capture(EvalThunk::new(id), Some(capture.finish()))
        .expect("tail-capturing thunk allocates");
    let token = begin(&mut evaluator, id, span, owner);
    let roots = evaluator.mutator_root_set().expect("lease roots enumerate");

    let plan = evaluator
        .heap
        .evacuation_plan(&roots)
        .expect("plan accepts tail lease roots");
    let report = plan.to_string();
    assert!(report.contains("\"hard_seed_objects\":1"));
    assert!(report.contains("\"transitive_retained_objects\":0"));
    assert!(report.contains("\"retained_objects\":1"));

    evaluator
        .abort_force_lease(id, span, token)
        .expect("tail-owning work restores");
}

#[cfg(all(feature = "collection_poll_probe", feature = "evacuation_plan_probe"))]
#[test]
fn detached_inherited_flat_owner_is_a_pinned_lease_root_not_a_hard_edge() {
    let (mut evaluator, id, span, _) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let captured = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"inherited flat value".to_vec()))
        .expect("inherited value allocates");
    let site = EvalNodeRef::new(EvalModuleId::ROOT, id);
    let mut capture = EvalFlatCaptureBuffer::new(site, 1);
    capture.push(captured).expect("donor capture appends");
    let (donor, tail) = evaluator
        .heap
        .alloc_thunk_with_flat_capture(EvalThunk::new(id), Some(capture.finish()))
        .expect("capture donor allocates");
    let env = EvalEnv::inline_flat(site, 1, tail.expect("donor owns a tail"))
        .expect("inherited flat environment builds");
    let owner = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, id, env))
        .expect("inheriting Node allocates");
    let token = begin(&mut evaluator, id, span, owner);
    let roots = evaluator.mutator_root_set().expect("lease roots enumerate");
    let donor_root = roots
        .roots()
        .iter()
        .find(|root| {
            matches!(root.source(), EvalRootSource::DetachedNodeThunkWork { .. })
                && root.value().raw_eq(donor)
        })
        .expect("inherited owner is rooted by the lease");
    evaluator
        .write_safepoint_root_writeback_value(donor_root.source(), donor, &mut [], &mut [])
        .expect("stable inherited owner validates as a pinned root");

    let plan = evaluator
        .heap
        .evacuation_plan(&roots)
        .expect("plan accepts inherited-owner lease root");
    let report = plan.to_string();
    assert!(report.contains("\"hard_seed_objects\":1"));
    assert!(report.contains("\"transitive_retained_objects\":0"));
    assert!(report.contains("\"retained_objects\":1"));

    evaluator
        .abort_force_lease(id, span, token)
        .expect("inherited flat work restores");
}

#[cfg(feature = "collection_poll_probe")]
#[test]
fn detached_apply_work_roots_are_writable_and_rollback_exactly() {
    let (mut evaluator, id, span, _) = fixture("null");
    enable_active_node_detachment(&mut evaluator);
    let function = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"function".to_vec()))
        .expect("function allocates");
    let argument = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"argument".to_vec()))
        .expect("argument allocates");
    let replacement = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"replacement".to_vec()))
        .expect("replacement allocates");
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, argument)
        .expect("Apply thunk allocates");
    let token = begin(&mut evaluator, id, span, apply);
    assert!(matches!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("source resolves")
            .kind(),
        EvalThunkKind::Released
    ));

    let roots = evaluator.mutator_root_set().expect("Apply roots enumerate");
    let source = roots
        .roots()
        .iter()
        .find(|root| {
            matches!(root.source(), EvalRootSource::DetachedNodeThunkWork { .. })
                && root.value().raw_eq(function)
        })
        .map(|root| root.source().clone())
        .expect("Apply function is a lease root");
    evaluator
        .write_safepoint_root_writeback_value(&source, replacement, &mut [], &mut [])
        .expect("Apply function writes back");
    evaluator
        .abort_force_lease(id, span, token)
        .expect("Apply work restores");

    let restored = evaluator.heap.get_thunk(apply).expect("Apply restores");
    assert_eq!(restored.cell().state(), Ok(ThunkState::Suspended));
    match restored.kind() {
        EvalThunkKind::Apply {
            function_value,
            argument_value,
            ..
        } => {
            assert!(function_value.raw_eq(replacement));
            assert!(argument_value.raw_eq(argument));
        }
        other => panic!("restored synthetic work changed shape: {other:?}"),
    }
}
