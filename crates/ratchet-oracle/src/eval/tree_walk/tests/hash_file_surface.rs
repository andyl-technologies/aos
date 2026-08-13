//! Tree-walk evaluator tests for hashFile cache-surface behavior.

use super::*;
use crate::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags, ParseCacheKey, PersistCache,
    PersistNodeMetadataKey, ValueHash,
};
use crate::string::NixString;

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
        synthetic_root_parse_key.as_durable_hash(),
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
