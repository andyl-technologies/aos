//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn fetch_tree_path_input_returns_locked_tree_metadata() {
    let dir = unique_temp_dir("fetch-tree-path");
    let source_dir = dir.join("source");
    fs::create_dir(&source_dir).expect("source directory creates");
    fs::write(source_dir.join("file.txt"), b"path-data").expect("source file writes");
    fs::create_dir(source_dir.join("sub")).expect("source subdirectory creates");
    fs::write(source_dir.join("sub").join("nested.txt"), b"nested")
        .expect("source nested file writes");
    let store_dir = unique_temp_dir("fetch-tree-path-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let path = nix_string_literal(&path_source(&source_dir));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {{ type = "path"; path = {path}; }};
                in {{
                  keys = builtins.attrNames x;
                  data = builtins.readFile "${{x.outPath}}/file.txt";
                  nested = builtins.readFile "${{x.outPath}}/sub/nested.txt";
                  narHash = x.narHash;
                  pathValue = x.outPath;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree path JSON parses");
    assert_eq!(
        value["keys"],
        serde_json::json!(["lastModified", "lastModifiedDate", "narHash", "outPath"])
    );
    assert_eq!(value["data"], "path-data");
    assert_eq!(value["nested"], "nested");
    assert!(
        value["narHash"]
            .as_str()
            .expect("narHash is a string")
            .starts_with("sha256-")
    );
    assert!(
        value["pathValue"]
            .as_str()
            .expect("pathValue is a string")
            .starts_with(path_source(&store_dir).as_str())
    );

    let nar_hash = value["narHash"].as_str().expect("narHash is a string");
    let denied_pure_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "path"; path = {path}; narHash = "{nar_hash}"; }}"#
        )),
        {
            let mut options = options.clone();
            options.set_eval_mode(EvalMode::Pure);
            options
        },
    )
    .expect_err("pure fetchTree path requires an allowed source path");
    assert!(matches!(
        denied_pure_error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            path: denied,
            mode: EvalMode::Pure,
            ..
        } if denied.as_slice() == source_dir.as_os_str().as_bytes()
    ));

    let mut pure_options = options.clone();
    pure_options.set_eval_mode(EvalMode::Pure);
    pure_options
        .add_allowed_path(source_dir.as_os_str().as_bytes().to_vec())
        .expect("pure fetchTree source path configures as allowed");
    let pure_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {{ type = "path"; path = {path}; narHash = "{nar_hash}"; }};
                in x.narHash
                "#
        ),
        pure_options,
    );
    assert_eq!(
        pure_json,
        serde_json::to_vec(nar_hash).expect("narHash JSON serializes")
    );

    let error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "path"; path = {path}; }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure fetchTree path requires narHash");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLockedInputRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("source temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_result_records_dynamic_repr_decision() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let result = FetchTreeResult {
        out_path: b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec(),
        nar_hash: b"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
        last_modified: Some(1_700_000_000),
        last_modified_date: Some(b"20231114221320".to_vec()),
        rev: Some(b"0123456789abcdef0123456789abcdef01234567".to_vec()),
        dirty_rev: Some(b"fedcba9876543210fedcba9876543210fedcba98".to_vec()),
        dirty_short_rev: Some(b"fedcba9".to_vec()),
        rev_count: Some(7),
        submodules: Some(true),
    };

    let value = evaluator
        .alloc_fetch_tree_result(ir.root, span, result)
        .expect("fetchTree result attrs allocate");

    let attrs = evaluator
        .heap
        .get_attrs(value)
        .expect("fetchTree result is attrs");
    assert_eq!(attrs.len(), 10);
    let metadata = evaluator
        .heap
        .get_attrs_metadata(value)
        .expect("fetchTree result metadata exists");
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let lexicographic_keys: Vec<Vec<u8>> = attrs
        .iter_lexicographic()
        .map(|entry| {
            evaluator
                .symbols
                .resolve(entry.key)
                .expect("fetchTree result key resolves")
                .to_vec()
        })
        .collect();
    assert_eq!(
        lexicographic_keys,
        vec![
            b"dirtyRev".to_vec(),
            b"dirtyShortRev".to_vec(),
            b"lastModified".to_vec(),
            b"lastModifiedDate".to_vec(),
            b"narHash".to_vec(),
            b"outPath".to_vec(),
            b"rev".to_vec(),
            b"revCount".to_vec(),
            b"shortRev".to_vec(),
            b"submodules".to_vec(),
        ],
    );
    let snapshot = evaluator
        .attr_telemetry
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 1);
    assert_eq!(snapshot.flat_decisions, 1);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 1);
    let stats = evaluator.attr_telemetry.order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_attr_entry_root_string_helper_rewrites_existing_entry_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let key = evaluator
        .intern_builtin_attr_symbol(ir.root, b"previous", span)
        .expect("entry key interns");
    let previous = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("existing entry thunk allocates");
    let mut entries = [AttrEntry::new(key, previous)];

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .alloc_tree_walk_string_with_attr_entry_roots(
            ir.root,
            span,
            &mut entries,
            NixString::from_bytes(b"next".to_vec()),
        )
        .expect("entry-rooted string allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(
        !entries[0].value.raw_eq(previous),
        "existing entry root was not rewritten after the string safepoint"
    );
    assert_eq!(entries[0].value.tag(), ValueTag::Thunk);
    assert_eq!(
        evaluator
            .heap()
            .generation(entries[0].value)
            .expect("existing entry root generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("allocated string generation is known"),
        HeapGeneration::Permanent
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_fetch_tree_result_strings_dispatch_with_registered_entry_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let result = FetchTreeResult {
        out_path: b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec(),
        nar_hash: b"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
        last_modified: Some(1_700_000_000),
        last_modified_date: Some(b"20231114221320".to_vec()),
        rev: Some(b"0123456789abcdef0123456789abcdef01234567".to_vec()),
        dirty_rev: Some(b"fedcba9876543210fedcba9876543210fedcba98".to_vec()),
        dirty_short_rev: Some(b"fedcba9".to_vec()),
        rev_count: Some(7),
        submodules: Some(true),
    };
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_fetch_tree_result(ir.root, span, result)
        })
        .expect("fetchTree result attrs allocate under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating fetchTree result strings"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("fetchTree attrs generation is known"),
        HeapGeneration::Permanent
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("fetchTree result is attrs");
    assert_eq!(attrs.len(), 10);
    let source_order: Vec<Vec<u8>> = attrs
        .iter_source_order()
        .map(|entry| {
            evaluator
                .symbols
                .resolve(entry.key)
                .expect("fetchTree result key resolves")
                .to_vec()
        })
        .collect();
    assert_eq!(
        source_order,
        [
            b"narHash".to_vec(),
            b"outPath".to_vec(),
            b"lastModified".to_vec(),
            b"lastModifiedDate".to_vec(),
            b"rev".to_vec(),
            b"shortRev".to_vec(),
            b"dirtyRev".to_vec(),
            b"dirtyShortRev".to_vec(),
            b"revCount".to_vec(),
            b"submodules".to_vec(),
        ]
    );
    let string_attrs = attrs
        .iter_by_symbol()
        .filter(|entry| entry.value.tag() == ValueTag::String)
        .count();
    assert_eq!(string_attrs, 7);
    let string_values: Vec<(Vec<u8>, Vec<u8>)> = attrs
        .iter_source_order()
        .filter_map(|entry| {
            (entry.value.tag() == ValueTag::String).then(|| {
                (
                    evaluator
                        .symbols
                        .resolve(entry.key)
                        .expect("fetchTree string key resolves")
                        .to_vec(),
                    evaluator
                        .heap()
                        .get_string(entry.value)
                        .expect("fetchTree string attr is heap-owned")
                        .bytes()
                        .to_vec(),
                )
            })
        })
        .collect();
    assert_eq!(
        string_values,
        [
            (
                b"narHash".to_vec(),
                b"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec()
            ),
            (
                b"outPath".to_vec(),
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec()
            ),
            (b"lastModifiedDate".to_vec(), b"20231114221320".to_vec()),
            (
                b"rev".to_vec(),
                b"0123456789abcdef0123456789abcdef01234567".to_vec()
            ),
            (b"shortRev".to_vec(), b"0123456".to_vec()),
            (
                b"dirtyRev".to_vec(),
                b"fedcba9876543210fedcba9876543210fedcba98".to_vec()
            ),
            (b"dirtyShortRev".to_vec(), b"fedcba9".to_vec()),
        ]
    );
    assert!(attrs.iter_by_symbol().all(|entry| {
        entry.value.tag() != ValueTag::String
            || evaluator
                .heap()
                .generation(entry.value)
                .is_ok_and(|generation| generation == HeapGeneration::Permanent)
    }));
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
        ],
        "fetchTree should dispatch metadata strings before final generated-attrset dispatch remains blocked"
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 8,
        "fetchTree should allocate seven metadata strings and the final attrset under GC stress"
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("fetchTree result allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

#[test]
fn configured_import_cache_preserves_fetch_tree_path_store_path_surface() {
    fn evaluate_fetch_tree_surface(
        source: &str,
        options: TreeWalkOptions,
    ) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator
            .eval_root()
            .expect("fetchTree expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("fetchTree outPath is a string")
            .bytes()
            .to_vec();
        (output, import_stats)
    }

    fn checked_store_path(output: &[u8], store_dir: &Path) -> PathBuf {
        let path = PathBuf::from(std::str::from_utf8(output).expect("store path is UTF-8"));
        assert!(
            path.starts_with(store_dir),
            "fetchTree store path {path:?} should stay under configured store dir {store_dir:?}"
        );
        path
    }

    fn assert_materialized_fetch_tree_file(output: &[u8], store_dir: &Path) {
        let path = checked_store_path(output, store_dir);
        assert_eq!(
            fs::read(path.join("file.txt")).expect("fetchTree materializes fixture file"),
            b"path-data"
        );
        assert_eq!(
            fs::read(path.join("sub").join("nested.txt"))
                .expect("fetchTree materializes nested fixture file"),
            b"nested"
        );
    }

    fn remove_store_path(output: &[u8], store_dir: &Path) {
        fs::remove_dir_all(checked_store_path(output, store_dir))
            .expect("materialized store path removes");
    }

    fn hot_string_surface_canaries(label: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let hot_canary = NixString::from_bytes(bytes.to_vec())
            .structural_hash_xxh3()
            .raw_for_tests();
        vec![
            (
                format!("{label} hot xxh3 decimal"),
                hot_canary.to_string().into_bytes(),
            ),
            (
                format!("{label} hot xxh3 hex"),
                format!("{hot_canary:016x}").into_bytes(),
            ),
            (
                format!("{label} hot xxh3 little-endian bytes"),
                hot_canary.to_le_bytes().to_vec(),
            ),
            (
                format!("{label} hot xxh3 big-endian bytes"),
                hot_canary.to_be_bytes().to_vec(),
            ),
        ]
    }

    let root = fs::canonicalize(unique_temp_dir(
        "import-cache-fetch-tree-path-surface-parity",
    ))
    .expect("temp directory canonicalizes");
    let source_dir = root.join("source");
    fs::create_dir(&source_dir).expect("source directory creates");
    fs::write(source_dir.join("file.txt"), b"path-data").expect("source file writes");
    fs::create_dir(source_dir.join("sub")).expect("source subdirectory creates");
    fs::write(source_dir.join("sub").join("nested.txt"), b"nested")
        .expect("source nested file writes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let store_dir = root.join("store");
    fs::create_dir(&store_dir).expect("store directory creates");
    let import_path = root.join("fetch-tree-path.nix");
    let source_path = path_source(&source_dir);
    let imported_source = nix_string_literal(&source_path).into_bytes();
    fs::write(&import_path, &imported_source).expect("fetchTree path import writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!(
        r#"let x = builtins.fetchTree {{ type = "path"; path = import {}; }}; in x.outPath"#,
        import_path.display()
    );

    let mut uncached_options = TreeWalkOptions::with_store_dir(path_bytes(&store_dir))
        .expect("store directory configures");
    uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (uncached_output, uncached_stats) = evaluate_fetch_tree_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));
    assert!(
        uncached_output.ends_with(b"-source"),
        "fetchTree path surface should expose the default source name: {uncached_output:?}"
    );
    assert_materialized_fetch_tree_file(&uncached_output, &store_dir);
    remove_store_path(&uncached_output, &store_dir);

    let mut miss_options = TreeWalkOptions::with_store_dir(path_bytes(&store_dir))
        .expect("store directory configures");
    miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_fetch_tree_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_output, uncached_output);
    assert_materialized_fetch_tree_file(&miss_output, &store_dir);
    remove_store_path(&miss_output, &store_dir);

    let mut hit_options = TreeWalkOptions::with_store_dir(path_bytes(&store_dir))
        .expect("store directory configures");
    hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_fetch_tree_surface(&source, hit_options);
    assert_eq!(hit_stats, (1, 0));
    assert_eq!(hit_output, uncached_output);
    assert_materialized_fetch_tree_file(&hit_output, &store_dir);
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_source(&imported_source)
            .is_complete(),
        "persistent hit should hydrate the runtime parse-cache entry"
    );

    let root_parse_key = ParseCacheKey::for_source(
        source.as_bytes(),
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let imported_parse_key = ParseCacheKey::for_source(
        &imported_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let file_key = ParseFileKey::for_source(&import_realpath, &imported_source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, imported_parse_key);
    assert!(
        PersistCache::open(&persist_root)
            .expect("persistent cache opens")
            .lookup_file_artifact(artifact_key)
            .expect("persistent file-artifact lookup succeeds")
            .is_some(),
        "fetchTree canary import should materialize a persistent file-artifact mapping"
    );

    let mut canaries =
        durable_hash_surface_canaries("root parse-cache BLAKE3", root_parse_key.as_durable_hash());
    canaries.extend(durable_hash_surface_canaries(
        "import parse-cache BLAKE3",
        imported_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "import file-content BLAKE3",
        file_key.content_hash().as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "fetchTree file payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(b"path-data"),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "fetchTree nested payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(b"nested"),
    ));
    canaries.extend(hot_string_surface_canaries(
        "fetchTree source path",
        source_path.as_bytes(),
    ));
    canaries.extend(hot_string_surface_canaries(
        "fetchTree source name",
        b"source",
    ));

    for (surface_name, output) in [
        ("cache-disabled fetchTree path surface", &uncached_output),
        ("persistent miss fetchTree path surface", &miss_output),
        ("persistent hit fetchTree path surface", &hit_output),
    ] {
        assert_surface_canaries_absent(surface_name, "store path", output, &canaries);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn fetch_tree_file_and_tarball_inputs_materialize_expected_store_paths() {
    let (file_dir, file_path) = temp_file_with_bytes("fetch-tree-file", b"plain-data");
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-tarball");
    let store_dir = unique_temp_dir("fetch-tree-file-tarball-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let file_url = nix_string_literal(&format!("file://{}", path_source(&file_path)));
    let tarball_url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  file = builtins.fetchTree {{ type = "file"; url = {file_url}; }};
                  fileUnpack = builtins.fetchTree {{ type = "file"; url = {file_url}; unpack = true; }};
                  tarball = builtins.fetchTree {{
                    type = "tarball";
                    url = {tarball_url};
                    narHash = "{recursive_digest}";
                    rev = "abcdef1234567890";
                    revCount = 7;
                  }};
                  tarballNoUnpack = builtins.fetchTree {{
                    type = "tarball";
                    url = {tarball_url};
                    narHash = "{recursive_digest}";
                    unpack = false;
                  }};
                in {{
                  fileKeys = builtins.attrNames file;
                  fileData = builtins.readFile file.outPath;
                  fileUnpackData = builtins.readFile fileUnpack.outPath;
                  tarballKeys = builtins.attrNames tarball;
                  tarballData = builtins.readFile "${{tarball.outPath}}/file.txt";
                  tarballNested = builtins.readFile "${{tarball.outPath}}/sub/nested.txt";
                  tarballNoUnpackData = builtins.readFile "${{tarballNoUnpack.outPath}}/file.txt";
                  tarballRev = tarball.rev;
                  tarballShortRev = tarball.shortRev;
                  tarballRevCount = tarball.revCount;
                }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree file/tarball JSON parses");
    assert_eq!(value["fileKeys"], serde_json::json!(["narHash", "outPath"]));
    assert_eq!(value["fileData"], "plain-data");
    assert_eq!(value["fileUnpackData"], "plain-data");
    assert_eq!(
        value["tarballKeys"],
        serde_json::json!([
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "rev",
            "revCount",
            "shortRev"
        ])
    );
    assert_eq!(value["tarballData"], "data");
    assert_eq!(value["tarballNested"], "inner");
    assert_eq!(value["tarballNoUnpackData"], "data");
    assert_eq!(value["tarballRev"], "abcdef1234567890");
    assert_eq!(value["tarballShortRev"], "abcdef1");
    assert_eq!(value["tarballRevCount"], 7);

    let error = eval_whnf_owned(&lower(&format!(
            r#"builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; }}"#
        )))
        .expect_err("wrong fetchTree tarball hash rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeHashMismatch { .. }
    ));

    fs::remove_dir_all(file_dir).expect("file temp directory removes");
    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_direct_path_and_tarball_reject_last_modified_mismatch() {
    fn current_unix_seconds() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after Unix epoch")
                .as_secs(),
        )
        .expect("current Unix time fits in Nix int")
    }

    fn mismatched_timestamp(actual: i64) -> i64 {
        actual
            .checked_add(31_536_000)
            .unwrap_or(actual - 31_536_000)
    }

    fn append_future_tar_bytes<W: std::io::Write>(
        builder: &mut tar::Builder<W>,
        path: &str,
        mode: u32,
        bytes: &[u8],
        mtime: i64,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).expect("tar path is valid");
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_mtime(u64::try_from(mtime).expect("test mtime is non-negative"));
        header.set_cksum();
        builder
            .append(&header, bytes)
            .expect("tar fixture entry appends");
    }

    let dir = unique_temp_dir("fetch-tree-metadata-mismatch");
    let source_dir = dir.join("source");
    fs::create_dir(&source_dir).expect("source directory creates");
    fs::write(source_dir.join("file.txt"), b"path-data").expect("source file writes");
    let future_tarball_last_modified = current_unix_seconds()
        .checked_add(31_536_000)
        .expect("future test mtime fits in Nix int");
    let archive_dir = unique_temp_dir("fetch-tree-metadata-tarball");
    let archive_path = archive_dir.join("root.tar.gz");
    let file = fs::File::create(&archive_path).expect("tarball fixture creates");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_future_tar_bytes(
        &mut builder,
        "root/file.txt",
        0o644,
        b"data",
        future_tarball_last_modified,
    );
    append_future_tar_bytes(
        &mut builder,
        "root/sub/nested.txt",
        0o644,
        b"inner",
        future_tarball_last_modified,
    );
    let encoder = builder.into_inner().expect("tar fixture finalizes");
    encoder.finish().expect("gzip fixture finalizes");
    let store_dir = unique_temp_dir("fetch-tree-metadata-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let path = nix_string_literal(&path_source(&source_dir));
    let tarball_url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  pathTree = builtins.fetchTree {{ type = "path"; path = {path}; }};
                  tarballTree = builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; }};
                in {{
                  pathLastModified = pathTree.lastModified;
                  tarballLastModified = tarballTree.lastModified;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree metadata JSON parses");
    let path_last_modified = value["pathLastModified"]
        .as_i64()
        .expect("path lastModified is an integer");
    let tarball_last_modified = value["tarballLastModified"]
        .as_i64()
        .expect("tarball lastModified is an integer");
    assert_eq!(tarball_last_modified, future_tarball_last_modified);
    let wrong_path_last_modified = mismatched_timestamp(path_last_modified);
    let wrong_tarball_last_modified = mismatched_timestamp(tarball_last_modified);

    let error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "path"; path = {path}; lastModified = {wrong_path_last_modified}; }}"#
        )),
        options.clone(),
    )
    .expect_err("direct path fetchTree rejects mismatched lastModified");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLastModifiedMismatch {
            expected,
            actual,
            ..
        } if expected == wrong_path_last_modified && actual == path_last_modified
    ));

    let error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; lastModified = {wrong_tarball_last_modified}; }}"#
        )),
        options,
    )
    .expect_err("direct tarball fetchTree rejects mismatched lastModified");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLastModifiedMismatch {
            expected,
            actual,
            ..
        } if expected == wrong_tarball_last_modified && actual == future_tarball_last_modified
    ));

    fs::remove_dir_all(dir).expect("source temp directory removes");
    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}
