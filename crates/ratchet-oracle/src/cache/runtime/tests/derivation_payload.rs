//! Derivation payload cache tests.

use super::*;

mod runtime_delegation;

mod static_output_revalidation;

#[test]
fn eval_cache_observes_derivation_aterm_expression() {
    let mut cache = EvalCache::new();
    let prior = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"old\")])";
    let changed = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"new\")])";

    let first = cache
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            prior,
        )
        .expect("first derivation ATerm observes");
    let same = cache
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            prior,
        )
        .expect("same derivation ATerm observes");
    let changed_reconsideration = cache
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            changed,
        )
        .expect("changed derivation ATerm observes");
    let node = cache
        .get_or_insert_expression_node(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            None,
        )
        .expect("existing expression node returns");

    assert_eq!(first.decision(), CutoffDecision::Propagate);
    assert_eq!(same.decision(), CutoffDecision::CutOff);
    assert_eq!(
        changed_reconsideration.decision(),
        CutoffDecision::Propagate
    );
    assert_eq!(
        cache.graph().node(node).expect("node exists").value_hash(),
        Some(derivation_aterm_hash(changed))
    );
}

#[test]
fn eval_cache_looks_up_clean_derivation_aterm_path() {
    let mut cache = EvalCache::new();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";
    let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";

    let reconsideration = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            drv_path,
        )
        .expect("derivation ATerm path observes");
    let lookup = cache
        .lookup_derivation_aterm_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("derivation ATerm path lookup succeeds");

    assert_eq!(reconsideration.decision(), CutoffDecision::Propagate);
    assert_eq!(lookup.as_deref(), Some(drv_path.as_slice()));
}

#[test]
fn eval_cache_derivation_aterm_path_hits_return_supplier_node_for_memo_read_edges() {
    let mut cache = EvalCache::new();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";
    let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";
    let parent = cache
        .get_or_insert_expression_node(
            identity(b"parent", 8),
            std::iter::empty::<DurableBlake3Hash>(),
            None,
        )
        .expect("parent node allocates");
    let reconsideration = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            drv_path,
        )
        .expect("derivation ATerm path observes");
    let hit = cache
        .lookup_derivation_aterm_path_hit(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("derivation ATerm path hit lookup succeeds")
        .expect("derivation ATerm path hit exists");

    assert_eq!(hit.node(), reconsideration.node());
    assert_eq!(hit.into_path_bytes(), drv_path);
    cache
        .record_memo_read_dependency(parent, reconsideration.node())
        .expect("memo-read edge records");
    assert!(
        cache
            .graph()
            .node(parent)
            .expect("parent node exists")
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
            .expect("parent memo-read edges exist")
            .contains(&reconsideration.node())
    );
}

#[test]
fn cached_derivation_aterm_paths_round_trip_through_persistent_encoding() {
    let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])".to_vec();
    let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv".to_vec();
    let payload = CachedDerivationAtermPath::new(aterm.clone(), drv_path.clone());
    let value_hash = payload.value_hash();
    let hash_derivation_modulo = [17; 32];
    let hashed_payload = CachedDerivationAtermPath::with_hash_derivation_modulo(
        aterm.clone(),
        drv_path.clone(),
        hash_derivation_modulo,
    );
    let hashed_value_hash = hashed_payload.value_hash();

    let encoded = payload
        .encode_persistent_payload()
        .expect("persistent payload encodes");
    let decoded = CachedDerivationAtermPath::decode_persistent_payload(&encoded)
        .expect("persistent payload decodes");
    let hashed_encoded = hashed_payload
        .encode_persistent_payload()
        .expect("hashed persistent payload encodes");
    let hashed_decoded = CachedDerivationAtermPath::decode_persistent_payload(&hashed_encoded)
        .expect("hashed persistent payload decodes");

    assert_eq!(
        DurableBlake3Hash::for_bytes(&encoded),
        value_hash.as_durable_hash()
    );
    assert_eq!(decoded.aterm_bytes(), aterm.as_slice());
    assert_eq!(decoded.path_bytes(), drv_path.as_slice());
    assert_eq!(decoded.hash_derivation_modulo(), None);
    assert_eq!(decoded.value_hash(), value_hash);
    assert_ne!(hashed_value_hash, value_hash);
    assert_eq!(
        DurableBlake3Hash::for_bytes(&hashed_encoded),
        hashed_value_hash.as_durable_hash()
    );
    assert_eq!(hashed_decoded.aterm_bytes(), aterm.as_slice());
    assert_eq!(hashed_decoded.path_bytes(), drv_path.as_slice());
    assert_eq!(
        hashed_decoded.hash_derivation_modulo(),
        Some(hash_derivation_modulo)
    );
    assert_eq!(hashed_decoded.value_hash(), hashed_value_hash);
}

#[test]
fn eval_cache_looks_up_clean_static_derivation_output_paths() {
    let mut cache = EvalCache::new();
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [7; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );

    let reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            output_paths.clone(),
        )
        .expect("static derivation output paths observe");
    let lookup = cache
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
        )
        .expect("static derivation output path lookup succeeds");

    assert_eq!(reconsideration.decision(), CutoffDecision::Propagate);
    assert_eq!(lookup, Some(output_paths));
}

#[test]
fn node_noncacheable_trace_removes_derivation_side_records() {
    let incomplete_source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/incomplete", b"same")],
        complete: false,
    };
    let uncacheable_source = TraceSource {
        trace: vec![ImpureInputFingerprint::current_time()],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";
    let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";
    let derivation = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            drv_path,
        )
        .expect("derivation ATerm path observes");
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [7; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    let static_outputs = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 8),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            output_paths.clone(),
        )
        .expect("static derivation output paths observe");
    assert_eq!(cache.derivation_aterm_path_record_count(), 1);
    assert_eq!(cache.static_derivation_output_path_record_count(), 1);

    cache
        .observe_impure_inputs_for_node(derivation.node(), &incomplete_source)
        .expect("incomplete trace invalidates derivation side record");
    cache
        .observe_impure_inputs_for_node(static_outputs.node(), &uncacheable_source)
        .expect("uncacheable trace invalidates static side record");

    assert_eq!(cache.derivation_aterm_path_record_count(), 0);
    assert_eq!(cache.static_derivation_output_path_record_count(), 0);
    assert_eq!(
        cache
            .graph()
            .node(derivation.node())
            .expect("derivation node exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        cache
            .graph()
            .node(static_outputs.node())
            .expect("static output node exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert!(
        cache
            .lookup_derivation_aterm_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm
            )
            .expect("derivation lookup succeeds")
            .is_none()
    );
    assert!(
        cache
            .lookup_static_derivation_output_paths(
                identity(b"derivation-outputs", 8),
                [durable_hash(b"free-var")],
                pre_output_aterm,
            )
            .expect("static output lookup succeeds")
            .is_none()
    );
}

#[test]
fn node_noncacheable_trace_removes_dependent_derivation_side_records() {
    let source = TraceSource {
        trace: vec![ImpureInputFingerprint::current_time()],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let root = cache
        .get_or_insert_expression_node(
            identity(b"root", 6),
            std::iter::empty::<DurableBlake3Hash>(),
            Some(value_hash(b"root")),
        )
        .expect("root node inserts");
    let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";
    let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";
    let derivation = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation-dependent", 7),
            [durable_hash(b"free-var")],
            aterm,
            drv_path,
        )
        .expect("derivation ATerm path observes");
    cache
        .graph
        .add_dependency(derivation.node(), root)
        .expect("derivation memo edge records");
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [7; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    let static_outputs = cache
        .observe_static_derivation_output_paths(
            identity(b"static-dependent", 8),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            output_paths.clone(),
        )
        .expect("static derivation output paths observe");
    cache
        .graph
        .add_dependency(static_outputs.node(), derivation.node())
        .expect("static output memo edge records");
    assert_eq!(cache.derivation_aterm_path_record_count(), 1);
    assert_eq!(cache.static_derivation_output_path_record_count(), 1);

    cache
        .observe_impure_inputs_for_node(root, &source)
        .expect("uncacheable trace invalidates dependent side records");

    assert_eq!(cache.derivation_aterm_path_record_count(), 0);
    assert_eq!(cache.static_derivation_output_path_record_count(), 0);
    for node in [root, derivation.node(), static_outputs.node()] {
        assert_eq!(
            cache
                .graph()
                .node(node)
                .expect("invalidated node exists")
                .freshness(),
            NodeFreshness::Dirty
        );
    }
    assert!(
        cache
            .lookup_derivation_aterm_path(
                identity(b"derivation-dependent", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("derivation lookup succeeds")
            .is_none()
    );
    assert!(
        cache
            .lookup_static_derivation_output_paths(
                identity(b"static-dependent", 8),
                [durable_hash(b"free-var")],
                pre_output_aterm,
            )
            .expect("static output lookup succeeds")
            .is_none()
    );
}

#[test]
fn replace_memo_read_dependencies_with_dirty_supplier_removes_derivation_side_records() {
    let mut cache = EvalCache::new();
    let supplier = cache
        .get_or_insert_expression_node(
            identity(b"dirty-supplier", 6),
            std::iter::empty::<DurableBlake3Hash>(),
            Some(value_hash(b"dirty-supplier")),
        )
        .expect("supplier inserts");
    cache
        .test_mark_dirty_node(supplier)
        .expect("supplier dirties");
    let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";
    let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";
    let derivation = cache
        .observe_derivation_aterm_expression_path(
            identity(b"dirty-dependent-derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            drv_path,
        )
        .expect("derivation ATerm path observes");
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [7; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    let static_outputs = cache
        .observe_static_derivation_output_paths(
            identity(b"dirty-dependent-static", 8),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            output_paths,
        )
        .expect("static derivation output paths observe");
    assert_eq!(cache.derivation_aterm_path_record_count(), 1);
    assert_eq!(cache.static_derivation_output_path_record_count(), 1);

    cache
        .replace_memo_read_dependencies(derivation.node(), [supplier])
        .expect("derivation memo-read dependencies replace");
    cache
        .replace_memo_read_dependencies(static_outputs.node(), [derivation.node()])
        .expect("static output memo-read dependencies replace");

    assert_eq!(cache.derivation_aterm_path_record_count(), 0);
    assert_eq!(cache.static_derivation_output_path_record_count(), 0);
    for node in [supplier, derivation.node(), static_outputs.node()] {
        assert_eq!(
            cache
                .graph()
                .node(node)
                .expect("invalidated node exists")
                .freshness(),
            NodeFreshness::Dirty
        );
    }
    assert!(
        cache
            .lookup_derivation_aterm_path(
                identity(b"dirty-dependent-derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("derivation lookup succeeds")
            .is_none()
    );
    assert!(
        cache
            .lookup_static_derivation_output_paths(
                identity(b"dirty-dependent-static", 8),
                [durable_hash(b"free-var")],
                pre_output_aterm,
            )
            .expect("static output lookup succeeds")
            .is_none()
    );
}

#[test]
fn dirty_memo_read_supplier_prevents_new_derivation_side_records() {
    let mut cache = EvalCache::new();
    let supplier = cache
        .get_or_insert_expression_node(
            identity(b"dirty-side-record-supplier", 6),
            std::iter::empty::<DurableBlake3Hash>(),
            Some(value_hash(b"dirty-side-record-supplier")),
        )
        .expect("supplier inserts");
    cache
        .test_mark_dirty_node(supplier)
        .expect("supplier dirties");
    let derivation_identity = identity(b"dirty-side-record-derivation", 7);
    let derivation = cache
        .get_or_insert_expression_node(
            derivation_identity,
            [durable_hash(b"free-var")],
            Some(value_hash(b"old-derivation")),
        )
        .expect("derivation node inserts");
    cache
        .record_memo_read_dependency(derivation, supplier)
        .expect("derivation memo-read edge records");
    let static_identity = identity(b"dirty-side-record-static", 8);
    let static_outputs = cache
        .get_or_insert_expression_node(
            static_identity,
            [durable_hash(b"free-var")],
            Some(value_hash(b"old-static")),
        )
        .expect("static output node inserts");
    cache
        .record_memo_read_dependency(static_outputs, supplier)
        .expect("static output memo-read edge records");
    let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [7; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );

    cache
        .observe_derivation_aterm_expression_path(
            derivation_identity,
            [durable_hash(b"free-var")],
            aterm,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
        )
        .expect("derivation ATerm path observes");
    cache
        .observe_static_derivation_output_paths(
            static_identity,
            [durable_hash(b"free-var")],
            pre_output_aterm,
            output_paths,
        )
        .expect("static derivation output paths observe");

    assert_eq!(cache.derivation_aterm_path_record_count(), 0);
    assert_eq!(cache.static_derivation_output_path_record_count(), 0);
    for node in [derivation, static_outputs] {
        assert_eq!(
            cache
                .graph()
                .node(node)
                .expect("side-record node exists")
                .freshness(),
            NodeFreshness::Dirty
        );
    }
}

#[test]
fn eval_cache_static_output_path_hits_return_supplier_node_for_memo_read_edges() {
    let mut cache = EvalCache::new();
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [7; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    let parent = cache
        .get_or_insert_expression_node(
            identity(b"parent-static", 8),
            std::iter::empty::<DurableBlake3Hash>(),
            None,
        )
        .expect("parent node allocates");
    let reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            output_paths.clone(),
        )
        .expect("static derivation output paths observe");
    let hit = cache
        .lookup_static_derivation_output_paths_hit(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
        )
        .expect("static output path hit lookup succeeds")
        .expect("static output path hit exists");

    assert_eq!(hit.node(), reconsideration.node());
    assert_eq!(hit.into_output_paths(), output_paths);
    cache
        .record_memo_read_dependency(parent, reconsideration.node())
        .expect("memo-read edge records");
    assert!(
        cache
            .graph()
            .node(parent)
            .expect("parent node exists")
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
            .expect("parent memo-read edges exist")
            .contains(&reconsideration.node())
    );
}

#[test]
fn cached_static_derivation_output_paths_round_trip_through_persistent_encoding() {
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [7; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    let payload = CachedStaticDerivationOutputPathsPayload::new(
        pre_output_aterm.to_vec(),
        output_paths.clone(),
    );
    let value_hash = payload.value_hash();

    let encoded = payload
        .encode_persistent_payload()
        .expect("persistent payload encodes");
    let decoded = CachedStaticDerivationOutputPathsPayload::decode_persistent_payload(&encoded)
        .expect("persistent payload decodes");

    assert_eq!(
        DurableBlake3Hash::for_bytes(&encoded),
        value_hash.as_durable_hash()
    );
    assert_eq!(decoded.pre_output_aterm_bytes(), pre_output_aterm);
    assert_eq!(decoded.value_hash(), value_hash);
    assert_eq!(decoded.into_output_paths(), output_paths);
}

#[test]
fn derivation_aterm_path_lookup_misses_without_path_record() {
    let mut cache = EvalCache::new();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[])";
    cache
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("derivation ATerm observes");

    let lookup = cache
        .lookup_derivation_aterm_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("derivation ATerm path lookup succeeds");

    assert!(lookup.is_none());
}

#[test]
fn derivation_aterm_path_lookup_misses_for_changed_or_dirty_nodes() {
    let mut cache = EvalCache::new();
    let prior = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"old\")])";
    let changed = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"new\")])";
    cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            prior,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
        )
        .expect("derivation ATerm path observes");

    let changed_lookup = cache
        .lookup_derivation_aterm_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            changed,
        )
        .expect("changed derivation ATerm lookup succeeds");
    assert!(changed_lookup.is_none());

    let node = cache
        .get_or_insert_expression_node(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            None,
        )
        .expect("existing derivation node returns");
    cache.graph.mark_dirty(node).expect("node dirties");
    let dirty_lookup = cache
        .lookup_derivation_aterm_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            prior,
        )
        .expect("dirty derivation ATerm lookup succeeds");

    assert!(dirty_lookup.is_none());
}

#[test]
fn derivation_aterm_path_revalidating_hit_cleans_matching_dirty_node() {
    let mut cache = EvalCache::new();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";
    let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";
    let observed = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            drv_path,
        )
        .expect("derivation ATerm path observes");
    cache
        .graph
        .mark_dirty(observed.node())
        .expect("node dirties");

    let hit = cache
        .lookup_derivation_aterm_path_hit_revalidating(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("revalidating derivation ATerm path lookup succeeds")
        .expect("matching dirty derivation ATerm side record revalidates");

    assert_eq!(hit.node(), observed.node());
    assert_eq!(
        hit.reconsideration()
            .expect("dirty hit reports reconsideration")
            .decision(),
        CutoffDecision::CutOff
    );
    assert_eq!(hit.into_path_bytes(), drv_path);
    assert_eq!(
        cache
            .graph()
            .node(observed.node())
            .expect("node exists")
            .freshness(),
        NodeFreshness::Clean
    );
}

#[test]
fn derivation_aterm_path_revalidating_hit_misses_changed_dirty_node() {
    let mut cache = EvalCache::new();
    let prior = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"old\")])";
    let changed = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"new\")])";
    let observed = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            prior,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
        )
        .expect("derivation ATerm path observes");
    cache
        .graph
        .mark_dirty(observed.node())
        .expect("node dirties");

    let hit = cache
        .lookup_derivation_aterm_path_hit_revalidating(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            changed,
        )
        .expect("revalidating changed derivation ATerm path lookup succeeds");

    assert!(hit.is_none());
    assert_eq!(
        cache
            .graph()
            .node(observed.node())
            .expect("node exists")
            .freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn derivation_aterm_path_observation_reconsiders_full_payload() {
    let mut cache = EvalCache::new();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";

    let first = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
        )
        .expect("first derivation ATerm path observes");
    let changed_path = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x.drv",
        )
        .expect("changed derivation ATerm path observes");
    let same = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x.drv",
        )
        .expect("same derivation ATerm path observes");
    let lookup = cache
        .lookup_derivation_aterm_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("derivation ATerm path lookup succeeds");

    assert_eq!(first.decision(), CutoffDecision::Propagate);
    assert_eq!(changed_path.decision(), CutoffDecision::Propagate);
    assert_eq!(same.decision(), CutoffDecision::CutOff);
    assert_eq!(
        lookup.as_deref(),
        Some(b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x.drv".as_slice())
    );
}

#[test]
fn static_derivation_output_path_lookup_misses_for_changed_or_dirty_nodes() {
    let mut cache = EvalCache::new();
    let prior = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let changed = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[(\"env\",\"new\")])";
    let output_paths = CachedDerivationOutputPaths::new(
        [8; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            prior,
            output_paths,
        )
        .expect("static derivation output paths observe");

    let changed_lookup = cache
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            changed,
        )
        .expect("changed static derivation output path lookup succeeds");
    assert!(changed_lookup.is_none());

    let node = cache
        .get_or_insert_expression_node(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            None,
        )
        .expect("existing static derivation output node returns");
    cache.graph.mark_dirty(node).expect("node dirties");
    let dirty_lookup = cache
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            prior,
        )
        .expect("dirty static derivation output path lookup succeeds");

    assert!(dirty_lookup.is_none());
}

#[test]
fn static_derivation_output_path_revalidating_hit_cleans_matching_dirty_node() {
    let mut cache = EvalCache::new();
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [8; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    let observed = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            output_paths.clone(),
        )
        .expect("static derivation output paths observe");
    cache
        .graph
        .mark_dirty(observed.node())
        .expect("node dirties");

    let hit = cache
        .lookup_static_derivation_output_paths_hit_revalidating(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
        )
        .expect("revalidating static output path lookup succeeds")
        .expect("matching dirty static-output side record revalidates");

    assert_eq!(hit.node(), observed.node());
    assert_eq!(
        hit.reconsideration()
            .expect("dirty hit reports reconsideration")
            .decision(),
        CutoffDecision::CutOff
    );
    assert_eq!(hit.into_output_paths(), output_paths);
    assert_eq!(
        cache
            .graph()
            .node(observed.node())
            .expect("node exists")
            .freshness(),
        NodeFreshness::Clean
    );
}
