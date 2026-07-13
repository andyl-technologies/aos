//! Split-out tests (part_2). See parent module.

use super::*;


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
            std::iter::empty::<ValueHash>(),
            None,
        )
        .expect("parent node allocates");
    let reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
            output_paths.clone(),
        )
        .expect("static derivation output paths observe");
    let hit = cache
        .lookup_static_derivation_output_paths_hit(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
            aterm,
        )
        .expect("derivation ATerm observes");

    let lookup = cache
        .lookup_derivation_aterm_path(identity(b"derivation", 7), [value_hash(b"free-var")], aterm)
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
            [value_hash(b"free-var")],
            prior,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
        )
        .expect("derivation ATerm path observes");

    let changed_lookup = cache
        .lookup_derivation_aterm_path(
            identity(b"derivation", 7),
            [value_hash(b"free-var")],
            changed,
        )
        .expect("changed derivation ATerm lookup succeeds");
    assert!(changed_lookup.is_none());

    let node = cache
        .get_or_insert_expression_node(identity(b"derivation", 7), [value_hash(b"free-var")], None)
        .expect("existing derivation node returns");
    cache.graph.mark_dirty(node).expect("node dirties");
    let dirty_lookup = cache
        .lookup_derivation_aterm_path(identity(b"derivation", 7), [value_hash(b"free-var")], prior)
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
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
            aterm,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
        )
        .expect("first derivation ATerm path observes");
    let changed_path = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [value_hash(b"free-var")],
            aterm,
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x.drv",
        )
        .expect("changed derivation ATerm path observes");
    let same = cache
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [value_hash(b"free-var")],
            aterm,
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x.drv",
        )
        .expect("same derivation ATerm path observes");
    let lookup = cache
        .lookup_derivation_aterm_path(identity(b"derivation", 7), [value_hash(b"free-var")], aterm)
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
            [value_hash(b"free-var")],
            prior,
            output_paths,
        )
        .expect("static derivation output paths observe");

    let changed_lookup = cache
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            changed,
        )
        .expect("changed static derivation output path lookup succeeds");
    assert!(changed_lookup.is_none());

    let node = cache
        .get_or_insert_expression_node(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            None,
        )
        .expect("existing static derivation output node returns");
    cache.graph.mark_dirty(node).expect("node dirties");
    let dirty_lookup = cache
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
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
