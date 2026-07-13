//! Force-cache revalidation tests for pathExists attr thunks.

use super::*;
mod part_1;
mod part_2;
mod part_3;
mod part_4;
mod part_5;
mod part_6;

fn first_class_find_file_apply_id(ir: &Ir) -> IrId {
    ir.arena
        .nodes()
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            if node.kind != IrKind::Apply {
                return None;
            }
            let IrData::Pair { first, second } = node.data else {
                return None;
            };
            let first = ir.arena.node(first)?;
            let second = ir.arena.node(second)?;
            let IrData::Symbol(symbol) = second.data else {
                return None;
            };
            (matches!(first.kind, IrKind::Apply | IrKind::LocalVar)
                && second.kind == IrKind::Str
                && ir.symbols.resolve(symbol) == Some(b"pkg/subdir".as_slice()))
            .then(|| IrId::new(index as u32))
        })
        .expect("first-class findFile final apply exists")
}

fn first_class_primop_subject_key_for_current_node(
    evaluator: &mut TreeWalk,
    id: IrId,
    builtin: Builtin,
) -> Option<DemandCacheKey> {
    let identity =
        evaluator.test_cache_first_class_primop_call_identity_for_current_node(id, builtin)?;
    let value_hashes =
        evaluator.test_first_class_primop_arg_hashes_for_current_apply(id, builtin)?;
    DemandCacheKey::for_free_vars(identity, value_hashes.iter().copied()).ok()
}

fn first_class_primop_persist_key_for_current_node(
    evaluator: &mut TreeWalk,
    id: IrId,
    builtin: Builtin,
) -> Option<PersistNodeMetadataKey> {
    let identity =
        evaluator.test_cache_first_class_primop_call_identity_for_current_node(id, builtin)?;
    let value_hashes =
        evaluator.test_first_class_primop_arg_hashes_for_current_apply(id, builtin)?;
    Some(PersistNodeMetadataKey::for_expression(
        identity,
        value_hashes.iter().copied(),
    ))
}

fn first_class_get_env_apply_id(ir: &Ir) -> IrId {
    let apply_ids = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| (node.kind == IrKind::Apply).then(|| IrId::new(index as u32)))
        .collect::<Vec<_>>();
    assert_eq!(
        apply_ids.len(),
        1,
        "test fixture should contain exactly one first-class getEnv apply"
    );
    apply_ids[0]
}

fn first_class_get_env_child_key_for_evaluator(
    evaluator: &mut TreeWalk,
    apply_id: IrId,
) -> DemandCacheKey {
    let builtin = lookup_builtin(b"getEnv").expect("getEnv builtin is registered");
    first_class_primop_subject_key_for_current_node(evaluator, apply_id, builtin)
        .expect("first-class getEnv child-call key builds")
}

fn assert_first_class_captured_arg_hits_child_call<C, A>(
    body: &str,
    source_name: &str,
    configure_options: C,
    expected_trace: Vec<ImpureInputFingerprint>,
    assert_value: A,
) where
    C: Fn(&mut TreeWalkOptions),
    A: Fn(&Ir, &mut TreeWalk, Value),
{
    let source = format!("{{ a = {body}; }}");
    let ir = lower(&source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for pass in 0..3 {
        let mut options = TreeWalkOptions::new();
        configure_options(&mut options);
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            source_name,
            source.as_str(),
            cache.clone(),
        );
        let value = force_attr_a(&mut evaluator, &ir, a);
        assert_value(&ir, &mut evaluator, value);
        assert_eq!(
            evaluator.impure_input_trace(),
            expected_trace.as_slice(),
            "first-class impure child-call trace should revalidate on every run"
        );
        if pass == 0 {
            assert_eq!(
                evaluator.stats().force_cache_hits(),
                0,
                "first run should compute the first-class child call cold"
            );
            assert!(
                evaluator.stats().force_cache_misses() > 0,
                "first run should record a cold first-class child-call miss"
            );
        } else if pass == 2 {
            assert!(
                evaluator.stats().thunks_forced() > 0,
                "the enclosing attr thunk must still evaluate when the child call hits"
            );
            assert_single_force_cache_impure_edge_owner_matches_trace(&cache, &expected_trace);
            assert!(
                evaluator.stats().force_cache_hits() > 0,
                "warm matching first-class child call should hit"
            );
            assert_eq!(
                evaluator.stats().force_cache_misses(),
                0,
                "fully warmed first-class child call should not miss"
            );
        }
    }
}

fn assert_single_force_cache_impure_edge_owner_matches_trace(
    runtime: &Arc<Mutex<EvalCacheRuntime>>,
    expected_trace: &[ImpureInputFingerprint],
) {
    let _ = single_force_cache_impure_edge_owner_key(runtime, expected_trace);
}

fn single_force_cache_impure_edge_owner_key(
    runtime: &Arc<Mutex<EvalCacheRuntime>>,
    expected_trace: &[ImpureInputFingerprint],
) -> DemandCacheKey {
    assert!(
        !expected_trace.is_empty(),
        "edge-exactness assertions require at least one input leaf"
    );
    let runtime = runtime.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    let graph = cache.graph();
    let expected_leaf_nodes = expected_trace
        .iter()
        .map(|fingerprint| {
            let fingerprint = fingerprint
                .as_cacheable()
                .expect("expected trace is cacheable");
            let key = DemandCacheKey::for_impure_input(fingerprint.identity().hash());
            graph.node_id_for_key(key).unwrap_or_else(|| {
                panic!(
                    "cache graph contains no leaf node for {:?} input",
                    fingerprint.kind()
                )
            })
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        expected_leaf_nodes.len(),
        expected_trace.len(),
        "each observed input fingerprint should map to one distinct graph leaf"
    );

    let impure_edge_owners = (0..cache.len())
        .filter_map(|index| {
            let raw = u32::try_from(index).expect("test graph has u32-addressable nodes");
            let node = DemandNodeId::new(raw);
            let dependencies = graph
                .node(node)
                .expect("node exists")
                .dependencies_in_group(DemandDependencyGroup::ImpureInput)?;
            (!dependencies.is_empty()).then(|| (node, dependencies.clone()))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        impure_edge_owners.len(),
        1,
        "a single first-class child-call node should own the impure-input edge group"
    );
    let (owner, dependencies) = &impure_edge_owners[0];
    assert_eq!(
        dependencies, &expected_leaf_nodes,
        "the first-class child call should depend on exactly the observed input leaves"
    );
    for dependency in dependencies {
        assert!(
            graph
                .node(*dependency)
                .expect("dependency exists")
                .dependents()
                .contains(owner),
            "input leaf should record the first-class child call as a reverse dependent"
        );
    }
    graph.node(*owner).expect("edge owner exists").key()
}

fn runtime_contains_node_key(runtime: &Arc<Mutex<EvalCacheRuntime>>, key: DemandCacheKey) -> bool {
    runtime
        .lock()
        .expect("cache lock is valid")
        .cache()
        .expect("cache is enabled")
        .graph()
        .node_id_for_key(key)
        .is_some()
}

fn assert_persistent_find_file_trace_log_contains(
    persist_root: &Path,
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> (PersistNodeMetadataKey, ValueHash) {
    assert_persistent_trace_log_contains(persist_root, expected_trace, context)
}

fn assert_persistent_trace_log_contains(
    persist_root: &Path,
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> (PersistNodeMetadataKey, ValueHash) {
    let expected = expected_cacheable_trace(expected_trace, context);
    let persist = PersistCache::open(persist_root).expect("persistent cache opens");
    let metadata_entries = persist
        .node_metadata_index()
        .latest_entries()
        .expect("persistent node metadata entries load");
    let trace_entries = persist
        .node_trace_log()
        .latest_entries()
        .expect("persistent node trace entries load");
    let live_matches = trace_entries
        .iter()
        .filter_map(|entry| {
            if entry.payload().is_tombstone() || entry.payload().inputs() != expected.as_slice() {
                return None;
            }
            let metadata_links_trace = metadata_entries.iter().any(|metadata| {
                metadata.key() == entry.key()
                    && metadata.value().materialized_value_hash() == Some(entry.value_hash())
            });
            metadata_links_trace.then_some((entry.key(), entry.value_hash()))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        live_matches.len(),
        1,
        "{context} should persist exactly one live force-cache verifying trace for the expected inputs"
    );
    live_matches[0]
}

fn expected_cacheable_trace(
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> Vec<crate::cache::CacheableInputFingerprint> {
    expected_trace
        .iter()
        .map(|input| {
            input
                .as_cacheable()
                .unwrap_or_else(|| panic!("{context} expected trace should be cacheable"))
                .clone()
        })
        .collect()
}

