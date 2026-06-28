//! Derivation payload cache tests.

use super::*;

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

    let encoded = payload
        .encode_persistent_payload()
        .expect("persistent payload encodes");
    let decoded = CachedDerivationAtermPath::decode_persistent_payload(&encoded)
        .expect("persistent payload decodes");

    assert_eq!(
        DurableBlake3Hash::for_bytes(&encoded),
        value_hash.as_durable_hash()
    );
    assert_eq!(decoded.aterm_bytes(), aterm.as_slice());
    assert_eq!(decoded.path_bytes(), drv_path.as_slice());
    assert_eq!(decoded.value_hash(), value_hash);
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

#[test]
fn static_derivation_output_path_revalidating_hit_misses_changed_dirty_node() {
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
    let observed = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            prior,
            output_paths,
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
            changed,
        )
        .expect("revalidating changed static output path lookup succeeds");

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
fn static_derivation_output_path_observation_reconsiders_full_payload() {
    let mut cache = EvalCache::new();
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let first = CachedDerivationOutputPaths::new(
        [1; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    let changed_path = CachedDerivationOutputPaths::new(
        [1; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x".to_vec(),
        )],
    );
    let changed_hash = CachedDerivationOutputPaths::new(
        [2; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x".to_vec(),
        )],
    );

    let first_reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            first,
        )
        .expect("first static output observation succeeds");
    let changed_path_reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            changed_path,
        )
        .expect("changed-path static output observation succeeds");
    let changed_hash_reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            changed_hash.clone(),
        )
        .expect("changed-hash static output observation succeeds");
    let same_reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            changed_hash.clone(),
        )
        .expect("same static output observation succeeds");
    let lookup = cache
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
        )
        .expect("static output lookup succeeds");

    assert_eq!(first_reconsideration.decision(), CutoffDecision::Propagate);
    assert_eq!(
        changed_path_reconsideration.decision(),
        CutoffDecision::Propagate
    );
    assert_eq!(
        changed_hash_reconsideration.decision(),
        CutoffDecision::Propagate
    );
    assert_eq!(same_reconsideration.decision(), CutoffDecision::CutOff);
    assert_eq!(lookup, Some(changed_hash));
}

#[test]
fn disabled_eval_cache_runtime_skips_derivation_aterm_path_lookup_and_observation() {
    let mut runtime = EvalCacheRuntime::disabled();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[])";

    let observation = runtime
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
        )
        .expect("disabled observation succeeds");
    let lookup = runtime
        .lookup_derivation_aterm_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("disabled lookup succeeds");

    assert!(observation.is_none());
    assert!(lookup.is_none());
    assert!(runtime.cache().is_none());
}

#[test]
fn disabled_eval_cache_runtime_skips_static_derivation_output_path_lookup_and_observation() {
    let mut runtime = EvalCacheRuntime::disabled();
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [9; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );

    let observation = runtime
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            output_paths,
        )
        .expect("disabled static output observation succeeds");
    let lookup = runtime
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
        )
        .expect("disabled static output lookup succeeds");

    assert!(observation.is_none());
    assert!(lookup.is_none());
    assert!(runtime.cache().is_none());
}

#[test]
fn enabled_eval_cache_runtime_delegates_derivation_aterm_path_roundtrip() {
    let mut runtime = EvalCacheRuntime::enabled();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[])";
    let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";

    let observation = runtime
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
            drv_path,
        )
        .expect("enabled observation succeeds")
        .expect("enabled runtime observes derivation ATerm path");
    let lookup = runtime
        .lookup_derivation_aterm_path(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("enabled lookup succeeds");

    assert_eq!(observation.decision(), CutoffDecision::Propagate);
    assert_eq!(lookup.as_deref(), Some(drv_path.as_slice()));
}

#[test]
fn enabled_eval_cache_runtime_delegates_static_derivation_output_path_roundtrip() {
    let mut runtime = EvalCacheRuntime::enabled();
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [10; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );

    let observation = runtime
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
            output_paths.clone(),
        )
        .expect("enabled static output observation succeeds")
        .expect("enabled runtime observes static output paths");
    let lookup = runtime
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [durable_hash(b"free-var")],
            pre_output_aterm,
        )
        .expect("enabled static output lookup succeeds");

    assert_eq!(observation.decision(), CutoffDecision::Propagate);
    assert_eq!(lookup, Some(output_paths));
}

#[test]
fn disabled_eval_cache_runtime_skips_derivation_aterm_observation() {
    let mut runtime = EvalCacheRuntime::disabled();

    let observation = runtime
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            b"Derive([],[],[],\":\",\":\",[],[])",
        )
        .expect("disabled observation succeeds");

    assert!(observation.is_none());
    assert!(runtime.cache().is_none());
}

#[test]
fn enabled_eval_cache_runtime_delegates_derivation_aterm_observation() {
    let mut runtime = EvalCacheRuntime::enabled();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[])";

    let first = runtime
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("enabled observation succeeds")
        .expect("enabled runtime observes derivation ATerm");
    let same = runtime
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [durable_hash(b"free-var")],
            aterm,
        )
        .expect("enabled observation succeeds")
        .expect("enabled runtime observes derivation ATerm");

    assert_eq!(first.decision(), CutoffDecision::Propagate);
    assert_eq!(same.decision(), CutoffDecision::CutOff);
    assert_eq!(runtime.cache().expect("cache is enabled").len(), 1);
}
