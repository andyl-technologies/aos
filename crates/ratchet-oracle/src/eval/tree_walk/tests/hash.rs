//! Tree-walk evaluator tests: hash.

use super::*;
use crate::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheFlags, ParseCacheKey,
    ParseFileKey, PersistCache, PersistFileArtifactKey, PersistNodeMetadataKey, ValueHash,
};
use crate::string::NixString;

#[test]
fn hash_string_primop_hashes_bytes() {
    assert_eq!(
        eval_string_bytes("builtins.hashString \"md5\" \"abc\""),
        b"900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        eval_string_bytes("builtins.hashString \"sha1\" \"abc\""),
        b"a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        eval_string_bytes("builtins.hashString \"sha256\" \"abc\""),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
            eval_string_bytes("builtins.hashString \"sha512\" \"abc\""),
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { hashString = type: value: \"local\"; }; in builtins.hashString \"sha256\" \"abc\""
        ),
        b"local"
    );
}

#[test]
fn configured_import_cache_preserves_hash_builtin_surface() {
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn push_durable_blake3_canaries(
        canaries: &mut Vec<(String, Vec<u8>)>,
        name: &str,
        hash: &DurableBlake3Hash,
    ) {
        canaries.push((format!("{name} BLAKE3 hex"), hash.to_hex().into_bytes()));
        canaries.push((format!("{name} BLAKE3 raw bytes"), hash.as_bytes().to_vec()));
        canaries.push((
            format!("{name} BLAKE3 Nix base32"),
            nix_compat::nixbase32::encode(&hash.as_bytes()).into_bytes(),
        ));
    }

    fn push_parse_key_canaries(
        canaries: &mut Vec<(String, Vec<u8>)>,
        name: &str,
        key: ParseCacheKey,
    ) {
        canaries.push((format!("{name} BLAKE3 hex"), key.to_hex().into_bytes()));
        canaries.push((format!("{name} BLAKE3 raw bytes"), key.as_bytes().to_vec()));
        canaries.push((
            format!("{name} BLAKE3 Nix base32"),
            nix_compat::nixbase32::encode(&key.as_bytes()).into_bytes(),
        ));
    }

    fn push_hot_string_canaries(canaries: &mut Vec<(String, Vec<u8>)>, name: &str, value: &[u8]) {
        let hot_canary = NixString::from_bytes(value.to_vec())
            .structural_hash_xxh3()
            .raw_for_tests();
        canaries.push((
            format!("{name} hot xxh3 decimal"),
            hot_canary.to_string().into_bytes(),
        ));
        canaries.push((
            format!("{name} hot xxh3 hex"),
            format!("{hot_canary:016x}").into_bytes(),
        ));
        canaries.push((
            format!("{name} hot xxh3 little-endian bytes"),
            hot_canary.to_le_bytes().to_vec(),
        ));
        canaries.push((
            format!("{name} hot xxh3 big-endian bytes"),
            hot_canary.to_be_bytes().to_vec(),
        ));
    }

    fn evaluate_hash_surface(source: &str, options: TreeWalkOptions) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator.eval_root().expect("hash expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("hash result is a string")
            .bytes()
            .to_vec();
        (output, import_stats)
    }

    let root = fs::canonicalize(unique_temp_dir("import-cache-hash-surface-parity"))
        .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let third_parse_root = root.join("third-parse-cache");
    let fourth_parse_root = root.join("fourth-parse-cache");
    let persist_root = root.join("persist-cache");
    let import_path = root.join("imported.nix");
    let imported_value = b"hash-surface-value";
    let changed_imported_value = b"changed-hash-surface-value";
    let imported_source = br#""hash-surface-value""#;
    let changed_imported_source = br#""changed-hash-surface-value""#;
    fs::write(&import_path, imported_source).expect("import source writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!(
        r#"let imported = import {}; in builtins.hashString "sha256" imported"#,
        import_path.display()
    );

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (uncached_output, uncached_stats) = evaluate_hash_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));

    let mut miss_options = TreeWalkOptions::new();
    miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_hash_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_output, uncached_output);

    let mut hit_options = TreeWalkOptions::new();
    hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_hash_surface(&source, hit_options);
    assert_eq!(hit_stats, (1, 0));
    assert_eq!(hit_output, uncached_output);
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_source(imported_source)
            .is_complete(),
        "persistent hit should hydrate the runtime parse-cache entry"
    );

    fs::write(&import_path, changed_imported_source).expect("changed import source writes");

    let mut changed_uncached_options = TreeWalkOptions::new();
    changed_uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (changed_uncached_output, changed_uncached_stats) =
        evaluate_hash_surface(&source, changed_uncached_options);
    assert_eq!(changed_uncached_stats, (0, 0));
    assert_ne!(changed_uncached_output, uncached_output);

    let mut changed_miss_options = TreeWalkOptions::new();
    changed_miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    changed_miss_options.set_parse_cache_root(&third_parse_root);
    changed_miss_options.set_persist_cache_root(&persist_root);
    let (changed_miss_output, changed_miss_stats) =
        evaluate_hash_surface(&source, changed_miss_options);
    assert_eq!(changed_miss_stats, (0, 1));
    assert_eq!(changed_miss_output, changed_uncached_output);

    let mut changed_hit_options = TreeWalkOptions::new();
    changed_hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    changed_hit_options.set_parse_cache_root(&fourth_parse_root);
    changed_hit_options.set_persist_cache_root(&persist_root);
    let (changed_hit_output, changed_hit_stats) =
        evaluate_hash_surface(&source, changed_hit_options);
    assert_eq!(changed_hit_stats, (1, 0));
    assert_eq!(changed_hit_output, changed_uncached_output);
    assert!(
        ParseCache::new(&fourth_parse_root)
            .entry_for_source(changed_imported_source)
            .is_complete(),
        "changed persistent hit should hydrate the runtime parse-cache entry"
    );

    let root_parse_key = ParseCacheKey::for_source(
        source.as_bytes(),
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let imported_parse_key = ParseCacheKey::for_source(
        imported_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let changed_imported_parse_key = ParseCacheKey::for_source(
        changed_imported_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let file_key = ParseFileKey::for_source(&import_realpath, imported_source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, imported_parse_key);
    let changed_file_key = ParseFileKey::for_source(&import_realpath, changed_imported_source);
    let changed_artifact_key =
        PersistFileArtifactKey::from_parse_file_key(&changed_file_key, changed_imported_parse_key);
    let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert!(
        persist_cache
            .lookup_file_artifact(artifact_key)
            .expect("persistent file-artifact lookup succeeds")
            .is_some(),
        "hash canary import should materialize a persistent file-artifact mapping"
    );
    assert!(
        persist_cache
            .lookup_file_artifact(changed_artifact_key)
            .expect("changed persistent file-artifact lookup succeeds")
            .is_some(),
        "changed hash canary import should materialize a persistent file-artifact mapping"
    );

    let mut canaries = Vec::new();
    push_parse_key_canaries(&mut canaries, "root parse-cache", root_parse_key);
    push_parse_key_canaries(
        &mut canaries,
        "original import parse-cache",
        imported_parse_key,
    );
    push_parse_key_canaries(
        &mut canaries,
        "changed import parse-cache",
        changed_imported_parse_key,
    );
    push_durable_blake3_canaries(
        &mut canaries,
        "original file-content",
        &file_key.content_hash(),
    );
    push_durable_blake3_canaries(
        &mut canaries,
        "changed file-content",
        &changed_file_key.content_hash(),
    );
    push_hot_string_canaries(&mut canaries, "original imported string", imported_value);
    push_hot_string_canaries(
        &mut canaries,
        "changed imported string",
        changed_imported_value,
    );

    let outputs = [
        ("original cache-disabled", &uncached_output),
        ("original persistent miss", &miss_output),
        ("original persistent hit", &hit_output),
        ("changed cache-disabled", &changed_uncached_output),
        ("changed persistent miss", &changed_miss_output),
        ("changed persistent hit", &changed_hit_output),
    ];
    for (output_name, output) in outputs {
        for (canary_name, canary) in &canaries {
            assert!(
                !contains_bytes(output, canary),
                "{canary_name} leaked into {output_name} hash builtin output: {output:?}"
            );
        }
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[derive(Debug)]
struct HashFileSurface {
    output: Vec<u8>,
    trace: Vec<ImpureInputFingerprint>,
    thunks_forced: u64,
    cache_hits: u64,
    force_cache_hits: u64,
    force_cache_misses: u64,
    persist_force_cache_hit_keys: Vec<PersistNodeMetadataKey>,
}

fn evaluate_hash_file_surface(
    ir: &Ir,
    options: TreeWalkOptions,
    eval_cache: EvalCacheRuntime,
) -> HashFileSurface {
    let outcome = eval_whnf_owned_with_options_realizer_and_eval_cache(
        ir,
        options,
        None,
        Arc::new(Mutex::new(eval_cache)),
    )
    .expect("hashFile expression evaluates");
    let output = outcome
        .heap()
        .get_string(outcome.value())
        .expect("hashFile result is a string")
        .bytes()
        .to_vec();
    HashFileSurface {
        output,
        trace: outcome.impure_input_trace().to_vec(),
        thunks_forced: outcome.stats().thunks_forced(),
        cache_hits: outcome.stats().cache_hits(),
        force_cache_hits: outcome.stats().force_cache_hits(),
        force_cache_misses: outcome.stats().force_cache_misses(),
        persist_force_cache_hit_keys: outcome.persist_force_cache_hit_keys().to_vec(),
    }
}

fn assert_persistent_hash_file_trace_log_contains(
    persist_root: &Path,
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> (PersistNodeMetadataKey, ValueHash) {
    let expected = expected_trace
        .iter()
        .map(|input| {
            input
                .as_cacheable()
                .unwrap_or_else(|| panic!("{context} expected trace should be cacheable"))
                .clone()
        })
        .collect::<Vec<_>>();
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

#[test]
fn configured_cache_preserves_guarded_hash_file_surface() {
    let persist_root = unique_temp_dir("hash-file-force-cache-surface-parity");
    let root = unique_temp_dir("hash-file-force-cache-source");
    let payload_path = root.join("payload.txt");
    let marker_path = root.join("marker");
    let payload = b"abc";
    let changed_payload = b"abcd";
    fs::write(&payload_path, payload).expect("payload writes");
    fs::write(&marker_path, b"present").expect("marker writes");
    let root = fs::canonicalize(&root).expect("source root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let payload_path = path_bytes(&root.join("payload.txt"));
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&marker_path, true).expect("fingerprint builds"),
        ImpureInputFingerprint::hash_file(&payload_path, payload).expect("fingerprint builds"),
    ];
    let hash_file_trace = vec![
        ImpureInputFingerprint::hash_file(&payload_path, payload).expect("fingerprint builds"),
    ];
    let changed_trace = vec![
        ImpureInputFingerprint::path_exists(&marker_path, true).expect("fingerprint builds"),
        ImpureInputFingerprint::hash_file(&payload_path, changed_payload)
            .expect("changed fingerprint builds"),
    ];
    let changed_hash_file_trace = vec![
        ImpureInputFingerprint::hash_file(&payload_path, changed_payload)
            .expect("changed fingerprint builds"),
    ];
    let source = r#"let
             b = builtins;
             forced = b.pathExists ./marker;
           in if forced then b.hashFile "sha256" ./payload.txt else "missing""#;
    let ir = lower(source);
    let expected_output = b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let changed_output = b"88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589";

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let uncached = evaluate_hash_file_surface(&ir, uncached_options, EvalCacheRuntime::disabled());
    assert_eq!(uncached.output, expected_output);
    assert_eq!(uncached.trace, expected_trace);
    assert_eq!(uncached.cache_hits, 0);
    assert_eq!(uncached.force_cache_hits, 0);
    assert_eq!(uncached.force_cache_misses, 0);

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    first_options.set_persist_cache_root(&persist_root);
    let first = evaluate_hash_file_surface(&ir, first_options, EvalCacheRuntime::enabled());
    assert_eq!(first.output, uncached.output);
    assert_eq!(first.trace, expected_trace);
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.force_cache_hits, 0);
    assert_eq!(first.force_cache_misses, 0);

    let mut materialize_options = TreeWalkOptions::with_eval_cache_enabled(true);
    materialize_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    materialize_options.set_persist_cache_root(&persist_root);
    let materialize =
        evaluate_hash_file_surface(&ir, materialize_options, EvalCacheRuntime::enabled());
    assert_eq!(materialize.output, uncached.output);
    assert_eq!(materialize.trace, expected_trace);
    assert_eq!(materialize.cache_hits, 0);
    assert_eq!(materialize.force_cache_hits, 0);
    assert!(
        materialize.force_cache_misses > 0,
        "materializing hashFile guard should miss before writing persistent force-cache payloads"
    );
    let original_trace_entry = assert_persistent_hash_file_trace_log_contains(
        &persist_root,
        &hash_file_trace,
        "materialized hashFile output surface",
    );
    let original_force_cache_canaries =
        persistent_force_cache_surface_canaries(&persist_root, &[&expected_trace]);

    let mut hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    hit_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    hit_options.set_persist_cache_root(&persist_root);
    let hit = evaluate_hash_file_surface(&ir, hit_options, EvalCacheRuntime::enabled());
    assert_eq!(hit.output, uncached.output);
    assert_eq!(hit.trace, expected_trace);
    assert!(
        hit.thunks_forced < materialize.thunks_forced,
        "fresh-runtime persistent hits should force fewer thunks than materializing recomputation"
    );
    assert!(hit.cache_hits > 0);
    assert!(hit.force_cache_hits > 0);
    assert_eq!(hit.force_cache_misses, 0);
    assert!(
        hit.persist_force_cache_hit_keys
            .contains(&original_trace_entry.0),
        "fresh-runtime hashFile output hit should load the original force-cache metadata key"
    );

    fs::write(root.join("payload.txt"), changed_payload).expect("payload changes");

    let mut uncached_changed_options = TreeWalkOptions::new();
    uncached_changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let uncached_changed =
        evaluate_hash_file_surface(&ir, uncached_changed_options, EvalCacheRuntime::disabled());
    assert_eq!(uncached_changed.output, changed_output);
    assert_ne!(uncached_changed.output, uncached.output);
    assert_eq!(uncached_changed.trace, changed_trace);
    assert_eq!(uncached_changed.cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_hits, 0);
    assert_eq!(uncached_changed.force_cache_misses, 0);

    let mut stale_options = TreeWalkOptions::with_eval_cache_enabled(true);
    stale_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    stale_options.set_persist_cache_root(&persist_root);
    let stale = evaluate_hash_file_surface(&ir, stale_options, EvalCacheRuntime::enabled());
    assert_eq!(stale.output, uncached_changed.output);
    assert_eq!(stale.trace, changed_trace);
    assert!(
        stale.force_cache_misses > 0,
        "stale hashFile output surface should miss before recomputing the changed payload"
    );
    assert!(
        stale.thunks_forced > 0,
        "stale hashFile output surface should fall back to ordinary forcing"
    );
    let changed_trace_entry = assert_persistent_hash_file_trace_log_contains(
        &persist_root,
        &changed_hash_file_trace,
        "stale hashFile output surface",
    );
    assert_eq!(
        changed_trace_entry.0, original_trace_entry.0,
        "stale hashFile output recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_trace_entry.1, original_trace_entry.1,
        "stale hashFile output recomputation should materialize a changed force-cache value"
    );

    let mut changed_hit_options = TreeWalkOptions::with_eval_cache_enabled(true);
    changed_hit_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    changed_hit_options.set_persist_cache_root(&persist_root);
    let changed_hit =
        evaluate_hash_file_surface(&ir, changed_hit_options, EvalCacheRuntime::enabled());
    assert_eq!(changed_hit.output, uncached_changed.output);
    assert_eq!(changed_hit.trace, changed_trace);
    assert!(changed_hit.cache_hits > 0);
    assert!(changed_hit.force_cache_hits > 0);
    assert_eq!(changed_hit.force_cache_misses, 0);
    assert!(
        changed_hit
            .persist_force_cache_hit_keys
            .contains(&changed_trace_entry.0),
        "fresh-runtime changed hashFile output hit should load the changed force-cache metadata key"
    );
    assert_eq!(
        assert_persistent_hash_file_trace_log_contains(
            &persist_root,
            &changed_hash_file_trace,
            "fresh-runtime changed hashFile output surface",
        ),
        changed_trace_entry,
        "fresh-runtime changed hashFile output reuse should keep the changed force-cache trace live"
    );

    let synthetic_root_parse_key = ParseCacheKey::for_source(
        source.as_bytes(),
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let hot_canary = NixString::from_bytes(uncached.output.clone())
        .structural_hash_xxh3()
        .raw_for_tests();
    let hot_decimal_canary = hot_canary.to_string();
    let hot_hex_canary = format!("{hot_canary:016x}");
    let hot_little_endian_canary = hot_canary.to_le_bytes();
    let hot_big_endian_canary = hot_canary.to_be_bytes();
    let changed_hot_canary = NixString::from_bytes(uncached_changed.output.clone())
        .structural_hash_xxh3()
        .raw_for_tests();
    let changed_hot_decimal_canary = changed_hot_canary.to_string();
    let changed_hot_hex_canary = format!("{changed_hot_canary:016x}");
    let changed_hot_little_endian_canary = changed_hot_canary.to_le_bytes();
    let changed_hot_big_endian_canary = changed_hot_canary.to_be_bytes();
    let mut canaries = durable_hash_surface_canaries(
        "synthetic root parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(synthetic_root_parse_key.as_bytes()),
    );
    canaries.extend(durable_hash_surface_canaries(
        "synthetic hashFile payload-content BLAKE3",
        DurableBlake3Hash::for_bytes(payload),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "synthetic changed hashFile payload-content BLAKE3",
        DurableBlake3Hash::for_bytes(changed_payload),
    ));
    let mut force_cache_canaries = original_force_cache_canaries;
    force_cache_canaries.extend(persistent_force_cache_surface_canaries(
        &persist_root,
        &[&changed_trace],
    ));
    assert!(
        force_cache_canaries
            .iter()
            .any(|(name, _)| name.starts_with("force materialized value BLAKE3")),
        "materializing hashFile guard should persist a forced value"
    );
    assert!(
        force_cache_canaries
            .iter()
            .any(|(name, _)| name.starts_with("force trace value BLAKE3")),
        "materializing hashFile guard should persist a verifying trace"
    );
    canaries.extend(force_cache_canaries);
    canaries.extend([
        (
            "hot xxh3 decimal".to_owned(),
            hot_decimal_canary.into_bytes(),
        ),
        ("hot xxh3 hex".to_owned(), hot_hex_canary.into_bytes()),
        (
            "hot xxh3 little-endian bytes".to_owned(),
            hot_little_endian_canary.to_vec(),
        ),
        (
            "hot xxh3 big-endian bytes".to_owned(),
            hot_big_endian_canary.to_vec(),
        ),
        (
            "changed hot xxh3 decimal".to_owned(),
            changed_hot_decimal_canary.into_bytes(),
        ),
        (
            "changed hot xxh3 hex".to_owned(),
            changed_hot_hex_canary.into_bytes(),
        ),
        (
            "changed hot xxh3 little-endian bytes".to_owned(),
            changed_hot_little_endian_canary.to_vec(),
        ),
        (
            "changed hot xxh3 big-endian bytes".to_owned(),
            changed_hot_big_endian_canary.to_vec(),
        ),
    ]);
    for (surface_name, surface) in [
        ("uncached hashFile surface", &uncached),
        ("cold hashFile surface", &first),
        ("materializing hashFile surface", &materialize),
        ("persistent-hit hashFile surface", &hit),
        ("changed uncached hashFile surface", &uncached_changed),
        ("stale hashFile surface", &stale),
        ("changed persistent-hit hashFile surface", &changed_hit),
    ] {
        assert_surface_canaries_absent(surface_name, "hashFile output", &surface.output, &canaries);
    }

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
    fs::remove_dir_all(root).expect("source temp directory removes");
}

#[test]
fn first_class_binary_builtin_selects_are_curried() {
    assert_eq!(
        eval_string_bytes("let h = builtins.hashString \"sha256\"; in h \"abc\""),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(eval("let add = builtins.add 1; in add 2").as_int(), Ok(3));
    assert_eq!(
        eval("let less = builtins.lessThan 1; in less 2").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let cmp = builtins.compareVersions \"1.2\"; in cmp \"1.10\"").as_int(),
        Ok(-1)
    );
    assert_eq!(
        eval_string_bytes("let get = builtins.getAttr \"a\"; in get { a = \"x\"; }"),
        b"x"
    );
    assert_eq!(
        eval("let has = builtins.hasAttr \"a\"; in has { a = 1; }").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(
            "let remove = builtins.removeAttrs { a = 1; b = 2; }; in remove [ \"a\" ] == { b = 2; }"
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
            eval("let intersect = builtins.intersectAttrs { a = 0; c = 0; }; in intersect { a = 1; b = 2; } == { a = 1; }").as_bool(),
            Ok(true)
        );
    assert_eq!(
        eval_list_ints(
            "let cat = builtins.catAttrs \"a\"; in cat [ { a = 1; } { b = 2; } { a = 3; } ]"
        ),
        vec![1, 3]
    );
    assert_eq!(
        eval_string_bytes("let join = builtins.concatStringsSep \",\"; in join [ \"a\" \"b\" ]"),
        b"a,b"
    );
    assert_eq!(
        eval("let s = builtins.seq (1 / 0); in builtins.isFunction s").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let s = builtins.seq 1; in builtins.length (s [ 1 (1 / 0) ])").as_int(),
        Ok(2)
    );
}

#[test]
fn first_class_binary_builtin_type_checks_left_before_right() {
    for (source, expected, actual) in [
        (
            "let cmp = builtins.compareVersions 1; in cmp (1 / 0)",
            "string",
            ValueTag::Int,
        ),
        (
            "let and = builtins.bitAnd true; in and (1 / 0)",
            "int",
            ValueTag::Bool,
        ),
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("left argument is rejected");

        let TreeWalkErrorKind::Type {
            expected: found_expected,
            actual: found_actual,
            ..
        } = error.kind()
        else {
            panic!("expected a type error for {source}, got {error:?}");
        };
        assert_eq!(found_expected, expected, "{source}");
        assert_eq!(found_actual, actual, "{source}");
    }
}

#[test]
fn first_class_ternary_builtin_selects_are_curried() {
    assert_eq!(
        eval("let fold = builtins.foldl' builtins.add; sum = fold 0; in sum [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval_string_bytes("let slice = builtins.substring 1; take2 = slice 2; in take2 \"abcd\""),
        b"bc"
    );
    assert_eq!(
        eval_string_bytes(
            "let replace = builtins.replaceStrings [ \"a\" ]; swap = replace [ \"b\" ]; in swap \"a\""
        ),
        b"b"
    );
}

#[test]
fn hash_string_primop_hashes_context_bearing_string_bytes() {
    let ir = lower("builtins.hashString \"sha256\" \"abc\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"abc".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_hash_string_primop_with_string_value(
            ir.root,
            root.span,
            algorithm,
            string,
            string_span,
            value,
        )
        .expect("hashString evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result is a string");

    assert_eq!(
        string.bytes(),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(!string.has_context());
}

#[test]
fn hash_string_primop_rejects_context_bearing_algorithm() {
    let ir = lower("builtins.hashString \"sha256\" (1 / 0)");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"sha256".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing algorithm allocates");

    let error = evaluator
        .eval_hash_algorithm(algorithm, algorithm_span, value, "hashString")
        .expect_err("hashString rejects algorithm string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: algorithm,
            op: "hashString",
        }
    );
    assert_eq!(error.span(), algorithm_span);
}

#[test]
fn hash_string_primop_checks_algorithm_before_string() {
    let ir = lower("builtins.hashString \"bad\" (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("unknown algorithm is rejected first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"bad".to_vec(),
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let ir = lower("builtins.hashString \"SHA256\" \"abc\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];

    let error = eval_whnf_owned(&ir).expect_err("algorithm names are case-sensitive");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"SHA256".to_vec(),
        }
    );
}

#[test]
fn hash_string_primop_type_checks_arguments() {
    let ir = lower("builtins.hashString 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("algorithm must be a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: algorithm,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let ir = lower("builtins.hashString \"sha256\" { outPath = \"abc\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string exists").span;

    let error = eval_whnf_owned(&ir).expect_err("string argument is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: string,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), string_span);
}

#[test]
fn convert_hash_primop_converts_formats() {
    let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base64\"; }}"
        )),
        b"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"nix32\"; }}"
        )),
        b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base32\"; }}"
        )),
        b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"sri\"; }}"
        )),
        b"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"sha256:{sha256}\"; toHashFormat = \"base16\"; }}"
        )),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = builtins.hashString \"md5\" \"abc\"; hashAlgo = \"md5\"; toHashFormat = \"nix32\"; }"
        ),
        b"3jgzhjhz9zjvbb0kyj7jc500ch"
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = builtins.hashString \"sha1\" \"abc\"; hashAlgo = \"sha1\"; toHashFormat = \"base64\"; }"
        ),
        b"qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
    );
    assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = builtins.hashString \"sha512\" \"abc\"; hashAlgo = \"sha512\"; toHashFormat = \"nix32\"; }"
            ),
            b"2gs8k559z4rlahfx0y688s49m2vvszylcikrfinm30ly9rak69236nkam5ydvly1ai7xac99vxfc4ii84hawjbk876blyk1jfhkbbyx"
        );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { convertHash = args: \"local\"; }; in builtins.convertHash { hash = 1 / 0; }"
        ),
        b"local"
    );
}

#[test]
fn convert_hash_primop_can_be_selected_as_a_function() {
    assert_eq!(
        eval_string_bytes(
            "let convert = builtins.convertHash; in convert { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn convert_hash_primop_checks_arguments_in_nix_order() {
    let ir = lower("builtins.convertHash 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("argument must be an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = 1 / 0; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
    ))
    .expect_err("hash is forced first");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
    ))
    .expect_err("hashAlgo is forced second");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = 1 / 0; }",
    ))
    .expect_err("toHashFormat is forced third");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn convert_hash_primop_reports_missing_attributes() {
    let ir = lower("builtins.convertHash { hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("convertHash requires hash");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing hash attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(evaluator.symbols.resolve(symbol), Some(b"hash".as_slice()));

    let ir = lower(
        "builtins.convertHash { hash = builtins.hashString \"sha256\" \"abc\"; hashAlgo = \"sha256\"; }",
    );
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("convertHash requires toHashFormat");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing toHashFormat attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(
        evaluator.symbols.resolve(symbol),
        Some(b"toHashFormat".as_slice())
    );
}

#[test]
fn convert_hash_primop_requires_direct_strings() {
    let ir = lower(
        "builtins.convertHash { hash = { outPath = \"abc\"; }; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
    );
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("hash is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = null; toHashFormat = \"base16\"; }",
    ))
    .expect_err("hashAlgo must be a string when present");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = { outPath = \"base16\"; }; }",
        ))
        .expect_err("toHashFormat is not coerced");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Attrs,
            ..
        }
    ));
}

#[test]
fn convert_hash_primop_rejects_invalid_hashes() {
    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"bad\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("unknown algorithm is rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm { algorithm, .. }
            if algorithm.as_slice() == b"bad"
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"bad\"; }",
    ))
    .expect_err("unknown format is rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashFormat { format, .. }
            if format.as_slice() == b"bad"
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("untyped hashes require hashAlgo");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashAlgorithmRequired { hash, .. }
            if hash.as_slice() == b"abc"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"md5\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("typed hashes must agree with hashAlgo");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashAlgorithmMismatch { expected, .. }
            if expected.as_slice() == b"md5"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("short hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashWrongLength { hash, algorithm, .. }
            if hash.as_slice() == b"abc" && algorithm.as_slice() == b"sha256"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid hex hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidBase16Hash { .. }
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"????????????????????????????????????????????\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid base64 hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidBase64Hash { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"sha256-invalid\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("invalid SRI hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidSriHash { .. }
    ));
}

#[test]
fn placeholder_primop_matches_cpp_nix_hash_scheme() {
    assert_eq!(
        eval_string_bytes(r#"builtins.placeholder "out""#),
        b"/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.placeholder "dev""#),
        b"/02qcpld1y6xhs5gz9bchpxaw0xdhmsp5dv88lh25r2ss44kh8dxz"
    );
    assert_eq!(
        eval("builtins.stringLength (builtins.placeholder \"out\")").as_int(),
        Ok(53)
    );
    assert_eq!(
        eval_string_bytes(r#"let p = builtins.placeholder; in p "out""#),
        b"/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9"
    );
    assert_eq!(
        eval_string_bytes(
            r#"let builtins = { placeholder = output: "local"; }; in builtins.placeholder "out""#
        ),
        b"local"
    );
}
