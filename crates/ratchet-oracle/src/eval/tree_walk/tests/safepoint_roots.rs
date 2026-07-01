//! Tree-walk safepoint root-set tests.

use super::*;
use crate::eval::heap::{EvalRoot, EvalRootSource, InternedRootTable};
use std::path::PathBuf;

#[test]
fn safepoint_roots_include_active_tree_walk_state_and_interned_roots() {
    let ir = lower("null");
    let mut evaluator = TreeWalk::new(&ir);
    let live = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"live-root".to_vec()))
        .expect("string allocates");

    let frame = EvalFrame::new(3).expect("frame allocates");
    frame.set(1, live).expect("frame slot sets");
    evaluator.env.push(frame);
    evaluator
        .with_scopes
        .push(EvalWithScope::new(EvalModuleId::ROOT, ir.root, live));
    evaluator.scoped_globals.push(live);
    evaluator
        .push_active_force_root(ir.root, Span::new(0, 0), live)
        .expect("force root pushes");
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            Span::new(0, 0),
            &[EvalPrimOpArg::new(ir.root, Span::new(0, 0), live)],
        )
        .expect("primop roots push");
    let suspended_frame = EvalFrame::new(2).expect("suspended frame allocates");
    suspended_frame
        .set(0, live)
        .expect("suspended frame slot sets");
    evaluator
        .reserve_suspended_env_root_frame(ir.root, Span::new(0, 0))
        .expect("suspended env root reserves");
    evaluator.push_suspended_env_roots(
        vec![suspended_frame],
        vec![EvalWithScope::new(EvalModuleId::ROOT, ir.root, live)],
        vec![live],
    );
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-import.nix"),
        ImportCacheEntry::Ready {
            value: live,
            trace: Some(Vec::new()),
            force_cache_trace_complete: true,
        },
    );

    let roots = evaluator
        .safepoint_root_set()
        .expect("safepoint roots build");
    let sources: Vec<_> = roots.roots().iter().map(EvalRoot::source).collect();

    assert!(sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 1 }));
    assert!(sources.contains(&&EvalRootSource::WithScope { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ScopedGlobal { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ForceContinuation { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::TreeWalkPrimopArgument {
        call_depth: 0,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedTreeWalkFrame {
        depth: 0,
        frame: 0,
        slot: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedWithScope {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedScopedGlobal {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::String,
        index: 0,
    }));
    assert!(!sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(!sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 2 }));

    let scan = evaluator
        .safepoint_heap_scan()
        .expect("safepoint heap scans");
    assert!(scan.roots().iter().any(|root| root.value().raw_eq(live)));
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(live))
    );
}

#[test]
fn active_safepoint_roots_are_removed_after_force_and_primop_errors() {
    let recursive = lower("let x = x; in x");
    let mut recursive_eval = TreeWalk::new(&recursive);
    recursive_eval
        .eval_root()
        .expect_err("recursive force reports blackhole");
    let recursive_roots = recursive_eval
        .safepoint_root_set()
        .expect("roots build after force error");
    assert!(recursive_roots.roots().iter().all(|root| {
        !matches!(
            root.source(),
            EvalRootSource::ForceContinuation { .. }
                | EvalRootSource::SuspendedTreeWalkFrame { .. }
                | EvalRootSource::SuspendedWithScope { .. }
                | EvalRootSource::SuspendedScopedGlobal { .. }
        )
    }));

    let bad_primop = lower("let add = builtins.add; in add 1 \"x\"");
    let mut primop_eval = TreeWalk::new(&bad_primop);
    primop_eval
        .eval_root()
        .expect_err("bad first-class primop reports type error");
    let primop_roots = primop_eval
        .safepoint_root_set()
        .expect("roots build after primop error");
    assert!(primop_roots.roots().iter().all(|root| {
        !matches!(
            root.source(),
            EvalRootSource::TreeWalkPrimopArgument { .. }
                | EvalRootSource::ForceContinuation { .. }
                | EvalRootSource::SuspendedTreeWalkFrame { .. }
                | EvalRootSource::SuspendedWithScope { .. }
                | EvalRootSource::SuspendedScopedGlobal { .. }
        )
    }));
}
