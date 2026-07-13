//! Split-out tests (part_5). See parent module.

use super::*;

#[test]
fn first_class_path_exists_with_captured_path_hits_child_call() {
    let root = unique_temp_dir("force-cache-first-class-path-exists-captured-path");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let source = "let marker = ./marker; f = builtins.pathExists; in f marker";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let expected_trace =
        vec![ImpureInputFingerprint::path_exists(&marker_path, true).expect("fingerprint builds")];

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let first_value = first.eval_root().expect("first pathExists call succeeds");
    assert_eq!(first_value.as_bool(), Ok(true));
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        first.stats().force_cache_hits(),
        0,
        "the first captured pathExists demand should be a cold child-call evaluation"
    );
    assert!(
        first.stats().force_cache_misses() > 0,
        "the first captured pathExists demand should record a cold cache miss"
    );
    drop(first);

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_value = second.eval_root().expect("second pathExists call succeeds");
    assert_eq!(second_value.as_bool(), Ok(true));
    assert_eq!(
        second.stats().force_cache_hits(),
        1,
        "the second captured pathExists demand should reuse already-recorded surrounding cache entries"
    );
    assert!(
        second.stats().force_cache_misses() > 0,
        "the second captured pathExists demand should materialize the child-call payload"
    );
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    drop(second);

    let mut third_options = TreeWalkOptions::new();
    third_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        third_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let third_value = third.eval_root().expect("third pathExists call succeeds");
    assert_eq!(third_value.as_bool(), Ok(true));
    assert!(
        third.stats().force_cache_hits() > 0,
        "matching captured path aliases should hit cached force-cache payloads"
    );
    assert_eq!(third.stats().force_cache_misses(), 0);
    assert_eq!(third.impure_input_trace(), expected_trace.as_slice());
    drop(third);

    fs::remove_file(root.join("marker")).expect("marker removed");

    let changed_trace =
        vec![ImpureInputFingerprint::path_exists(&marker_path, false).expect("fingerprint builds")];
    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache,
    );
    let changed_value = changed
        .eval_root()
        .expect("changed pathExists call succeeds");
    assert_eq!(changed_value.as_bool(), Ok(false));
    assert!(
        changed.stats().force_cache_misses() > 0,
        "stale captured pathExists traces should miss and recompute"
    );
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn first_class_hash_file_with_captured_algorithm_and_path_hits_child_call() {
    let root = unique_temp_dir("force-cache-first-class-hash-file-captured-args");
    fs::write(root.join("target"), b"hash file payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = r#"let
        algorithm = "sha256";
        target = ./target;
        f = builtins.hashFile;
      in f algorithm target"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let expected_hash = b"4ae6266cc082134ea87e6fbf8b747c078f4e6d42f44179b8936f61a524133982";
    let expected_trace = vec![
        ImpureInputFingerprint::hash_file(&target_path, b"hash file payload")
            .expect("fingerprint builds"),
    ];

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let first_value = first.eval_root().expect("first hashFile call succeeds");
    assert_eq!(
        first
            .heap()
            .get_string(first_value)
            .expect("hashFile result is a string")
            .bytes(),
        expected_hash
    );
    assert_eq!(first.impure_input_trace(), expected_trace.as_slice());
    assert_eq!(
        first.stats().force_cache_hits(),
        0,
        "the first captured hashFile demand should be a cold child-call evaluation"
    );
    assert!(
        first.stats().force_cache_misses() > 0,
        "the first captured hashFile demand should record cold cache misses"
    );
    drop(first);

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_value = second.eval_root().expect("second hashFile call succeeds");
    assert_eq!(
        second
            .heap()
            .get_string(second_value)
            .expect("hashFile result is a string")
            .bytes(),
        expected_hash
    );
    assert!(
        second.stats().force_cache_hits() > 0,
        "the second captured hashFile demand should reuse already-recorded surrounding cache entries"
    );
    assert!(
        second.stats().force_cache_misses() > 0,
        "the second captured hashFile demand should materialize the child-call payload"
    );
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());
    drop(second);

    let mut third_options = TreeWalkOptions::new();
    third_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        third_options,
        "default.nix",
        source,
        cache,
    );
    let third_value = third.eval_root().expect("third hashFile call succeeds");
    assert_eq!(
        third
            .heap()
            .get_string(third_value)
            .expect("hashFile result is a string")
            .bytes(),
        expected_hash
    );
    assert!(
        third.stats().force_cache_hits() > 0,
        "matching captured hashFile args should hit cached force-cache payloads"
    );
    assert_eq!(third.stats().force_cache_misses(), 0);
    assert_eq!(third.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn first_class_unary_import_and_file_builtins_with_captured_args_hit_child_calls() {
    let root = unique_temp_dir("force-cache-first-class-unary-captured-args");
    fs::write(root.join("dep.nix"), b"7").expect("import source writes");
    fs::write(root.join("target"), b"read file payload").expect("target writes");
    fs::create_dir(root.join("dir")).expect("readDir directory creates");
    fs::write(root.join("dir").join("alpha"), b"entry").expect("readDir entry writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dep_path = path_bytes(&root.join("dep.nix"));
    let target_path = path_bytes(&root.join("target"));
    let dir_path = path_bytes(&root.join("dir"));

    assert_first_class_captured_arg_hits_child_call(
        "let target = ./dep.nix; f = import; in f target",
        "first-class-import-captured-arg.nix",
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base is absolute");
        },
        vec![ImpureInputFingerprint::import(&dep_path, b"7").expect("import fingerprint builds")],
        |_, _, value| assert_eq!(value.as_int(), Ok(7)),
    );

    assert_first_class_captured_arg_hits_child_call(
        "let target = ./target; f = builtins.readFile; in f target",
        "first-class-read-file-captured-arg.nix",
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base is absolute");
        },
        vec![
            ImpureInputFingerprint::read_file(&target_path, b"read file payload")
                .expect("readFile fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("readFile result is a string")
                    .bytes(),
                b"read file payload"
            );
        },
    );

    assert_first_class_captured_arg_hits_child_call(
        "let target = ./target; f = builtins.readFileType; in f target",
        "first-class-read-file-type-captured-arg.nix",
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base is absolute");
        },
        vec![
            ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Regular)
                .expect("readFileType fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("readFileType result is a string")
                    .bytes(),
                b"regular"
            );
        },
    );

    assert_first_class_captured_arg_hits_child_call(
        "let target = ./dir; f = builtins.readDir; in f target",
        "first-class-read-dir-captured-arg.nix",
        |options| {
            options
                .set_path_literal_base(path_bytes(&root))
                .expect("path base is absolute");
        },
        vec![
            ImpureInputFingerprint::read_dir(
                &dir_path,
                [DirEntryInput::new(b"alpha", FileTypeForInput::Regular)],
            )
            .expect("readDir fingerprint builds"),
        ],
        |_, evaluator, value| {
            let alpha = evaluator.symbols.intern(b"alpha").expect("alpha interns");
            let attrs = evaluator
                .heap()
                .get_attrs(value)
                .expect("readDir result is an attrset");
            let alpha_value = attrs.get(alpha).expect("alpha entry exists");
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(alpha_value)
                    .expect("alpha entry is a string")
                    .bytes(),
                b"regular"
            );
        },
    );

    let env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_CAPTURED_ARG";
    assert_first_class_captured_arg_hits_child_call(
        r#"let target = "AOS_FORCE_CACHE_FIRST_CLASS_CAPTURED_ARG"; f = builtins.getEnv; in f target"#,
        "first-class-get-env-captured-arg.nix",
        |options| {
            options.set_env_var(env_name.to_vec(), b"env payload".to_vec());
        },
        vec![
            ImpureInputFingerprint::get_env(env_name, Some(b"env payload"))
                .expect("getEnv fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("getEnv result is a string")
                    .bytes(),
                b"env payload"
            );
        },
    );

    let formal_env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_FORMAL_ARG";
    assert_first_class_captured_arg_hits_child_call(
        r#"({ target }: let f = builtins.getEnv; in f target)
          (builtins.fromJSON ''{"target":"AOS_FORCE_CACHE_FIRST_CLASS_FORMAL_ARG"}'')"#,
        "first-class-get-env-captured-formal-arg.nix",
        |options| {
            options.set_env_var(formal_env_name.to_vec(), b"formal env payload".to_vec());
        },
        vec![
            ImpureInputFingerprint::get_env(formal_env_name, Some(b"formal env payload"))
                .expect("formal getEnv fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("formal getEnv result is a string")
                    .bytes(),
                b"formal env payload"
            );
        },
    );

    let preforced_env_name = b"AOS_FORCE_CACHE_FIRST_CLASS_PREFORCED_ARG";
    assert_first_class_captured_arg_hits_child_call(
        r#"let
          target = "AOS_FORCE_CACHE_FIRST_CLASS_PREFORCED_ARG";
          f = builtins.getEnv;
        in builtins.seq target (f target)"#,
        "first-class-get-env-captured-preforced-arg.nix",
        |options| {
            options.set_env_var(
                preforced_env_name.to_vec(),
                b"preforced env payload".to_vec(),
            );
        },
        vec![
            ImpureInputFingerprint::get_env(preforced_env_name, Some(b"preforced env payload"))
                .expect("preforced getEnv fingerprint builds"),
        ],
        |_, evaluator, value| {
            assert_eq!(
                evaluator
                    .heap()
                    .get_string(value)
                    .expect("preforced getEnv result is a string")
                    .bytes(),
                b"preforced env payload"
            );
        },
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_effectful_forced_inline_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-effectful-changed");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("thunk force succeeds")
            .as_bool(),
        Ok(true)
    );

    fs::remove_file(root.join("marker")).expect("marker removed");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed force recomputes");

    assert_eq!(forced_changed.as_bool(), Ok(false));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn effectful_forced_inline_thunks_hit_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-hit");
    let root = unique_temp_dir("force-cache-persistent-effectful");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let parent_identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"persistent-effectful-memo-read-parent",
        )),
        IrId::new(9),
    );
    let parent_subject = ForceCacheSubject {
        lookup_identity: Some(parent_identity),
        pure_observation_identity: Some(parent_identity),
        impure_observation_identity: Some(parent_identity),
        metadata_identity: Some(parent_identity),
        persistent_clear_identity: Some(parent_identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
    };

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let shared_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        shared_runtime.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let parent_node = second
        .active_force_cache_node_for_subject(Some(&parent_subject))
        .expect("parent active node allocates");
    second
        .active_memo_read_nodes
        .push(ActiveMemoReadNode::new(parent_node));
    let forced_again = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("persistent effectful hit succeeds");
    let active = second
        .active_memo_read_nodes
        .pop()
        .expect("test-controlled active node pops");
    assert_eq!(
        active.node(),
        parent_node,
        "test-controlled active node stack should be balanced"
    );
    second.replace_active_memo_reads(active);

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "fresh runtimes should rehydrate stable effectful payloads from disk"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), true)
            .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent hit revalidation must remain visible to enclosing force traces"
    );
    drop(second);

    {
        let runtime = shared_runtime.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        assert_eq!(
            cache.len(),
            3,
            "persistent hits should seed the active parent, child expression node, and input leaf"
        );
        assert_eq!(
            cache_nodes_with_dependencies(cache),
            2,
            "the active parent depends on the child expression, which keeps its revalidated input edge"
        );
        let parent = cache
            .graph()
            .node(parent_node)
            .expect("parent node is present");
        let child_node = *parent
            .dependencies_in_group(crate::cache::DemandDependencyGroup::MemoRead)
            .expect("parent has memo-read edges")
            .iter()
            .next()
            .expect("memo-read edge exists");
        assert!(parent.dependencies().contains(&child_node));
        let child = cache
            .graph()
            .node(child_node)
            .expect("child node is present");
        assert!(
            child
                .dependencies_in_group(crate::cache::DemandDependencyGroup::ImpureInput)
                .expect("child has impure-input edges")
                .iter()
                .next()
                .is_some(),
            "trace-backed persistent hit should preserve the revalidated impure-input edge"
        );
        assert!(child.dependents().contains(&parent_node));
    }

    fs::remove_dir_all(&persist_root).expect("persistent temp tree removed");

    let mut third_options = TreeWalkOptions::with_eval_cache_enabled(true);
    third_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        third_options,
        "default.nix",
        source,
        shared_runtime,
    );
    let forced_from_memory = force_attr_a(&mut third, &ir, a);

    assert_eq!(forced_from_memory.as_bool(), Ok(true));
    assert_eq!(
        third.stats().thunks_forced(),
        0,
        "persistent-hit runtime seeding should allow later in-memory reuse"
    );
    assert_eq!(third.stats().cache_hits(), 1);
    assert_eq!(third.stats().cache_misses(), 0);
    assert_eq!(
        third.impure_input_trace(),
        expected_trace.as_slice(),
        "seeded runtime hits must still revalidate into the enclosing trace"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn dirty_persistent_effectful_force_cache_hit_counts_early_cutoff() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-dirty-cutoff");
    let root = unique_temp_dir("force-cache-persistent-effectful-dirty");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    drop(first);

    let shared_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut prime_options = TreeWalkOptions::with_eval_cache_enabled(true);
    prime_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut prime = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        prime_options,
        "default.nix",
        source,
        shared_runtime.clone(),
    );
    let (primed, subject) = force_attr_a_with_impure_observation_subject(&mut prime, &ir, a);
    assert_eq!(primed.as_bool(), Ok(true));
    let identity = subject
        .lookup_identity
        .expect("trace-backed attr has a lookup identity");
    let owner_key =
        DemandCacheKey::for_free_vars(identity, subject.free_var_value_hashes.iter().copied())
            .expect("owner key builds");
    {
        let mut runtime = shared_runtime.lock().expect("cache lock is valid");
        assert_eq!(
            runtime
                .invalidate_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied()
                )
                .expect("payload invalidates"),
            Some(true)
        );
        let cache = runtime.cache().expect("cache is enabled");
        let owner = cache
            .graph()
            .node_id_for_key(owner_key)
            .expect("forced expression node remains");
        assert_eq!(
            cache
                .graph()
                .node(owner)
                .expect("owner node exists")
                .freshness(),
            crate::cache::NodeFreshness::Dirty
        );
    }
    drop(prime);

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        shared_runtime,
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "persistent hit should replay without forcing the thunk body"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    assert_eq!(
        second.stats().early_cutoffs(),
        1,
        "persistent hit runtime seeding should count same-hash dirty cutoff"
    );
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), true)
            .expect("fingerprint builds"),
    ];
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(&persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_effectful_forced_inline_thunks_miss_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-changed");
    let root = unique_temp_dir("force-cache-persistent-effectful-stale");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    drop(first);

    fs::remove_file(root.join("marker")).expect("marker removed");

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced_changed = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_changed.as_bool(), Ok(false));
    assert_eq!(
        second.stats().thunks_forced(),
        1,
        "stale persistent traces should fall back to ordinary forcing"
    );
    assert_eq!(second.stats().cache_hits(), 0);
    assert_eq!(second.stats().cache_misses(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), false)
            .expect("fingerprint builds"),
    ];
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

