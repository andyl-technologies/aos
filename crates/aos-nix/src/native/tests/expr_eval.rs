//! Tests for `NixNative::eval_expr` strict-JSON evaluation and its
//! fallback-eligibility boundaries.

use super::*;
use crate::heap::HeapMemoryBudget;

const PARSE_ERROR_SOURCE: &str = "let x = ; in x";

#[test]
fn native_eval_error_reports_invalid_ir_as_eval_error() {
    let error = TreeWalkError::new(
        TreeWalkErrorKind::InvalidNodeKind {
            id: IrId::new(0),
            kind: IrKind::Formal,
        },
        Span::new(0, 1),
    );

    let native = native_eval_error_with_trace(error, None, EvalTraceStyle::Summary);

    let NativeEvalError::EvalError { message } = native else {
        panic!("invalid IR should not fall back to native CLI");
    };
    assert!(message.contains("invalid tree-walk node Formal"));
}

#[test]
fn native_expression_eval_renders_strict_json() -> Result<()> {
    let native = NixNative::new(0)?;

    assert_eq!(native.eval_expr("1 + 1")?, "2");
    assert_eq!(native.eval_expr("1 # trailing comment")?, "1");
    assert_eq!(native.eval_expr(r#""x""#)?, r#""x""#);
    assert_eq!(
        native.eval_expr(r#"{ b = 1; a = [ true null "x" ]; }"#)?,
        r#"{"a":[true,null,"x"],"b":1}"#
    );

    Ok(())
}

#[test]
fn native_jit_enabled_eval_gates_and_matches_tree_walk() -> Result<()> {
    // With the JIT enabled but promotion gated by default (every current tier-1
    // shape is net-negative on wall time), a hot `r = k` binding is gated rather
    // than promoted: nothing is compiled or dispatched, yet the result stays
    // byte-identical to the plain tree walk. Dispatch itself is exercised by the
    // engine-level differential tests under the force-promote flag.
    let expr = "let g = k: { r = k; }; \
         in builtins.foldl' (acc: item: acc + item.r) 0 \
         (builtins.genList (i: g (i + 1)) 40)";

    let (tree_walk_json, _) = NixNative::new(0)?.eval_expr_with_stats(expr)?;

    let mut options = TreeWalkOptions::new();
    options.set_jit_tier1_publish_enabled(true);
    let (jit_json, stats) = NixNative::with_options(0, options)?.eval_expr_with_stats(expr)?;

    assert_eq!(
        jit_json, tree_walk_json,
        "JIT-enabled result must match the tree walk"
    );
    assert_eq!(
        stats.tier1_promoted(),
        0,
        "promotion is gated by default, got {stats:?}"
    );
    assert_eq!(
        stats.tier1_dispatched(),
        0,
        "no dispatch without promotion, got promoted={} dispatched={} deopted={}",
        stats.tier1_promoted(),
        stats.tier1_dispatched(),
        stats.tier1_deopted(),
    );

    Ok(())
}

#[test]
fn native_expression_eval_reports_tier_a_heap_stats_without_gc_work() -> Result<()> {
    let native = NixNative::new(0)?;

    let (json, stats) =
        native.eval_expr_with_stats(r#"let f = x: { a = [ x "tier-a" ]; }; in f 1"#)?;

    assert_eq!(json, r#"{"a":[1,"tier-a"]}"#);
    assert!(stats.heap_chunks() > 0);
    assert!(stats.heap_mapped_bytes() >= stats.heap_reserved_bytes());
    assert!(stats.heap_reserved_bytes() >= stats.heap_used_bytes());
    assert!(stats.heap_used_bytes() > 0);
    assert!(stats.permanent_heap_chunks() > 0);
    assert!(stats.permanent_heap_mapped_bytes() >= stats.permanent_heap_reserved_bytes());
    assert!(stats.permanent_heap_reserved_bytes() >= stats.permanent_heap_used_bytes());
    assert!(stats.permanent_heap_used_bytes() > 0);
    assert_eq!(stats.gc_bytes(), 0);
    assert_eq!(stats.gc_pause_us(), 0);
    assert_eq!(stats.tier_promotions(), 0);
    assert_eq!(stats.deopts(), 0);
    assert_eq!(stats.heap_tier_b_admission_worker_records(), 0);
    assert_eq!(stats.heap_tier_b_admission_permanent_shared_records(), 0);
    assert_eq!(stats.heap_tier_b_admission_generation_rewrites(), 0);

    Ok(())
}

#[test]
fn native_expression_eval_reports_heap_tier_b_admission_stats() -> Result<()> {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_tier_b_transition_admission_enabled(true);
    // FV-3: generation rewrites live on record-table worker objects, so this
    // fixture selects the Tier-B B2 scaffolding placement.
    options.set_record_worker_closures_for_gc_scaffolding(true);
    let native = NixNative::with_options(0, options)?;

    let (json, stats) =
        native.eval_expr_with_stats(r#"let f = x: { a = [ x "tier-b" ]; }; in f 1"#)?;

    assert_eq!(json, r#"{"a":[1,"tier-b"]}"#);
    assert!(stats.heap_tier_b_admission_worker_records() > 0);
    assert_eq!(
        stats.heap_tier_b_admission_generation_rewrites(),
        stats.heap_tier_b_admission_worker_records()
    );

    Ok(())
}

#[test]
fn native_expression_eval_forces_empty_foldl_initial_for_attrs_consumers() -> Result<()> {
    let native = NixNative::new(0)?;

    assert_eq!(
        native.eval_expr("(builtins.foldl' (acc: subdir: acc // subdir) {} []) // { z = 1; }")?,
        r#"{"z":1}"#
    );
    assert_eq!(
        native.eval_expr("(builtins.foldl' (acc: subdir: acc // subdir) { z = 1; } []).z")?,
        "1"
    );

    Ok(())
}

#[test]
fn native_expression_eval_replays_generated_import_source_seed() -> Result<()> {
    let root = unique_temp_dir("native-expression-generated-seed");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let source_file = root.join("corpus-root.nix");
    fs::write(
        &source_file,
        "{ system ? builtins.currentSystem }: { pkgs.generated = { z = system; a = [ true null \"pkg\" ]; }; }\n",
    )?;
    let native = NixNative::new(0)?;
    let source = format!(
        "let
           loaded = import (builtins.toPath {});
           root = if builtins.isFunction loaded then loaded {{ system = \"x86_64-linux\"; }} else loaded;
           path = [ \"pkgs\" \"generated\" ];
         in
           builtins.foldl' (value: name: builtins.getAttr name value) root path",
        nix_string_literal(&path_bytes(&source_file)?)?
    );

    assert_eq!(
        native.eval_expr(&source)?,
        r#"{"a":[true,null,"pkg"],"z":"x86_64-linux"}"#
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_restricted_import_obeys_allowed_paths() -> Result<()> {
    let root = unique_temp_dir("native-expression-restricted-import");
    let allowed = root.join("allowed");
    let denied = root.join("denied");
    fs::create_dir_all(&allowed)?;
    fs::create_dir_all(&denied)?;
    let allowed = fs::canonicalize(allowed)?;
    let denied = fs::canonicalize(denied)?;
    let allowed_file = allowed.join("value.nix");
    let denied_file = denied.join("value.nix");
    fs::write(&allowed_file, "{ ok = true; }")?;
    fs::write(&denied_file, "{ ok = false; }")?;
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options.add_allowed_path(path_bytes(&allowed)?)?;
    let native = NixNative::with_options(0, options)?;

    assert_eq!(
        native.eval_expr(&format!(
            "import (builtins.toPath {})",
            nix_string_literal(&path_bytes(&allowed_file)?)?
        ))?,
        r#"{"ok":true}"#
    );
    let error = native
        .eval_expr(&format!(
            "import (builtins.toPath {})",
            nix_string_literal(&path_bytes(&denied_file)?)?
        ))
        .expect_err("restricted eval-json import must reject unallowed paths");
    assert!(matches!(
        error.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::EvalError { message }) if message.contains("forbids filesystem access")
    ));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_restricted_scoped_import_obeys_allowed_paths() -> Result<()> {
    let root = unique_temp_dir("native-expression-restricted-scoped-import");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let source_file = root.join("scoped.nix");
    fs::write(&source_file, "{ y = x + 1; }")?;
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options.add_allowed_path(path_bytes(&root)?)?;
    let native = NixNative::with_options(0, options)?;

    assert_eq!(
        native.eval_expr(&format!(
            "builtins.scopedImport {{ x = 2; }} (builtins.toPath {})",
            nix_string_literal(&path_bytes(&source_file)?)?
        ))?,
        r#"{"y":3}"#
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_uses_configured_parse_cache() -> Result<()> {
    let root = unique_temp_dir("native-expression-parse-cache");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let cache_root = root.join("parse");
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(&cache_root);
    let native = NixNative::with_options(0, options)?;
    let expr = "1 + 1";

    assert_eq!(native.eval_expr(expr)?, "2");

    let cache = ParseCache::new(&cache_root);
    let entry = cache.entry_for_source(json_wrapper_source(expr).as_bytes());
    assert!(
        entry.is_complete(),
        "native expression evaluation should populate the parse-cache entry"
    );

    assert_eq!(native.eval_expr(expr)?, "2");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_refreshes_parse_cache_analysis_facts() -> Result<()> {
    let root = unique_temp_dir("native-expression-parse-cache-analysis");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let cache_root = root.join("parse");
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(&cache_root);
    let native = NixNative::with_options(0, options)?;
    let expr = "(x: x + 1) (1 + 2)";
    let source = json_wrapper_source(expr);

    let (json, stats) = native.eval_expr_with_stats(expr)?;

    assert_eq!(json, "4");
    assert!(
        stats.thunks_elided() > 0,
        "analyzed native expression should elide a strict thunk"
    );
    assert_parse_cache_has_non_conservative_facts(&cache_root, source.as_bytes())?;

    let (cached_json, cached_stats) = native.eval_expr_with_stats(expr)?;
    assert_eq!(cached_json, "4");
    assert!(
        cached_stats.thunks_elided() > 0,
        "cached analyzed native expression should preserve refreshed facts"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_materializes_persistent_parse_cache_without_source_path() -> Result<()> {
    use crate::cache::{PersistCache, PersistParseArtifactKey};

    let root = unique_temp_dir("native-expression-no-persist-file-cache");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let cache_root = root.join("parse");
    let persist_root = root.join("persist");
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(&cache_root);
    options.set_persist_cache_root(&persist_root);
    let native = NixNative::with_options(0, options)?;
    let expr = "1 + 1";
    let source = json_wrapper_source(expr);

    assert_eq!(native.eval_expr(expr)?, "2");

    let cache = ParseCache::new(&cache_root);
    let parse_key = cache.key_for_source(source.as_bytes());
    assert!(cache.entry_for_key(parse_key).is_complete());
    let persist = PersistCache::open(&persist_root)?;
    assert!(
        persist
            .lookup_parse_artifact(PersistParseArtifactKey::from_parse_cache_key(parse_key))?
            .is_some(),
        "raw expression eval should write a parse-keyed persistent artifact"
    );
    assert_eq!(
        fs::metadata(persist.layout().file_artifact_index_path())?.len(),
        0,
        "raw expression eval should not synthesize a persistent file-artifact key"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_persists_refreshed_analysis_facts_without_source_path() -> Result<()> {
    use crate::cache::{PersistCache, PersistParseArtifactKey};

    let root = unique_temp_dir("native-expression-persist-parse-analysis");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let first_parse_root = root.join("first-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let expr = "(x: x + 1) (1 + 2)";
    let source = json_wrapper_source(expr);

    let mut first_options = TreeWalkOptions::new();
    first_options.set_parse_cache_root(&first_parse_root);
    first_options.set_persist_cache_root(&persist_root);
    let first_native = NixNative::with_options(0, first_options)?;
    let (first_json, first_stats) = first_native.eval_expr_with_stats(expr)?;
    assert_eq!(first_json, "4");
    assert!(
        first_stats.thunks_elided() > 0,
        "first analyzed native expression should elide a strict thunk"
    );
    assert_parse_cache_has_non_conservative_facts(&first_parse_root, source.as_bytes())?;
    let first_cache = ParseCache::new(&first_parse_root);
    let parse_key = first_cache.key_for_source(source.as_bytes());
    assert!(
        PersistCache::open(&persist_root)?
            .lookup_parse_artifact(PersistParseArtifactKey::from_parse_cache_key(parse_key))?
            .is_some(),
        "native expression should persist the refreshed parse artifact"
    );
    let probe_parse_root = root.join("probe-parse");
    let persisted = PersistCache::open(&persist_root)?
        .load_parse_cache_bytes_from_index(&ParseCache::new(&probe_parse_root), source.as_bytes())?
        .expect("persisted raw expression artifact hydrates");
    assert_ir_has_non_conservative_facts(&persisted.ir);

    let observed_hits = Arc::new(Mutex::new(Vec::new()));
    let observed_hits_for_hook = Arc::clone(&observed_hits);
    let mut second_options = TreeWalkOptions::new();
    second_options.set_parse_cache_root(&second_parse_root);
    second_options.set_persist_cache_root(&persist_root);
    let mut second_native = NixNative::with_options(0, second_options)?;
    second_native.set_persistent_parse_hit_hook(move |hit| {
        observed_hits_for_hook
            .lock()
            .expect("persistent parse hit observations lock")
            .push(hit);
    });

    let (second_json, second_stats) = second_native.eval_expr_with_stats(expr)?;

    assert_eq!(second_json, "4");
    assert!(
        second_stats.thunks_elided() > 0,
        "persistent analyzed native expression should preserve refreshed facts"
    );
    assert_parse_cache_has_non_conservative_facts(&second_parse_root, source.as_bytes())?;
    assert_eq!(
        observed_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .clone(),
        vec![NativePersistentParseHit::Bytes]
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_hydrates_persistent_parse_cache_without_source_path() -> Result<()> {
    use crate::cache::{MaterializationDecision, ParseCacheMeta, PersistCache};

    let root = unique_temp_dir("native-expression-persist-parse-hit");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let seed_parse_root = root.join("seed-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let expr = "1 + 1";
    let source = json_wrapper_source(expr);
    let marker = "persist-raw-expression-marker.nix";
    let seed_parse = ParseCache::new(&seed_parse_root);
    let parsed = seed_parse.load_or_parse_bytes(source.as_bytes(), Some(marker.to_owned()))?;
    PersistCache::open(&persist_root)?.materialize_parse_cache_entry_indexed(
        parsed.key,
        &parsed.entry,
        MaterializationDecision::Materialize,
    )?;
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(&second_parse_root);
    options.set_persist_cache_root(&persist_root);
    let native = NixNative::with_options(0, options)?;

    assert_eq!(native.eval_expr(expr)?, "2");

    let hydrated_entry = ParseCache::new(&second_parse_root).entry_for_source(source.as_bytes());
    assert!(
        hydrated_entry.is_complete(),
        "persistent raw expression hit should hydrate the fresh parse-cache entry"
    );
    let meta = fs::read_to_string(hydrated_entry.meta_path())?;
    let meta = ParseCacheMeta::from_toml(&meta)?;
    assert_eq!(meta.source_hint.as_deref(), Some(marker));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_ignores_persistent_parse_cache_open_failure() -> Result<()> {
    let root = unique_temp_dir("native-expression-persist-open-failure");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let cache_root = root.join("parse");
    let persist_root = root.join("persist-is-file");
    fs::write(&persist_root, b"not a persistent cache directory")?;
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(&cache_root);
    options.set_persist_cache_root(&persist_root);
    let native = NixNative::with_options(0, options)?;
    let expr = "1 + 1";
    let source = json_wrapper_source(expr);

    assert_eq!(native.eval_expr(expr)?, "2");

    let cache = ParseCache::new(&cache_root);
    assert!(
        cache.entry_for_source(source.as_bytes()).is_complete(),
        "raw expression eval should fall back to the normal parse cache"
    );
    assert_eq!(
        fs::read(&persist_root)?,
        b"not a persistent cache directory",
        "advisory persistent open failure should not mutate the file path"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_ignores_stale_persistent_parse_artifact() -> Result<()> {
    use crate::cache::{
        PERSIST_BLOB_PACK_HEADER_LEN, PersistBlobLocation, PersistCache, PersistFileBlobHash,
        PersistParseArtifactIndexEntry, PersistParseArtifactIndexValue, PersistParseArtifactKey,
    };

    let root = unique_temp_dir("native-expression-persist-stale-hit");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let cache_root = root.join("parse");
    let persist_root = root.join("persist");
    let expr = "1 + 1";
    let source = json_wrapper_source(expr);
    let parse_cache = ParseCache::new(&cache_root);
    let parse_key = parse_cache.key_for_source(source.as_bytes());
    let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let stale_value = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"missing raw expression artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
    );
    PersistCache::open(&persist_root)?.record_parse_artifact(
        PersistParseArtifactIndexEntry::new(artifact_key, stale_value),
    )?;
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(&cache_root);
    options.set_persist_cache_root(&persist_root);
    let native = NixNative::with_options(0, options)?;

    assert_eq!(native.eval_expr(expr)?, "2");

    assert!(
        parse_cache.entry_for_key(parse_key).is_complete(),
        "stale durable raw expression hit should fall back to parsing"
    );
    assert!(
        PersistCache::open(&persist_root)?
            .lookup_parse_artifact(artifact_key)?
            .is_some(),
        "fallback parse should preserve or replace a durable parse-artifact mapping"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_ignores_persistent_parse_writeback_failure() -> Result<()> {
    use crate::cache::PersistCache;

    let root = unique_temp_dir("native-expression-persist-write-failure");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let cache_root = root.join("parse");
    let persist_root = root.join("persist");
    PersistCache::open(&persist_root)?;
    let parse_artifact_index = PersistCache::open(&persist_root)?
        .layout()
        .parse_artifact_index_path();
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(&cache_root);
    options.set_persist_cache_root(&persist_root);
    let mut native = NixNative::with_options(0, options)?;
    let hook_index = parse_artifact_index.clone();
    native.set_persist_cache_hook(move |_| {
        let mut permissions = fs::metadata(&hook_index)
            .expect("parse artifact index metadata")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&hook_index, permissions).expect("parse artifact index readonly");
    });
    let expr = "1 + 1";
    let source = json_wrapper_source(expr);

    assert_eq!(native.eval_expr(expr)?, "2");

    let cache = ParseCache::new(&cache_root);
    assert!(
        cache.entry_for_source(source.as_bytes()).is_complete(),
        "parse should still populate the normal parse-cache entry"
    );
    assert_eq!(
        fs::metadata(&parse_artifact_index)?.len(),
        0,
        "failed advisory writeback should not record a parse-artifact mapping"
    );

    let mut permissions = fs::metadata(&parse_artifact_index)?.permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&parse_artifact_index, permissions)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_ingests_impure_trace_when_eval_cache_enabled() -> Result<()> {
    let root = unique_temp_dir("native-expression-eval-cache");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let input = root.join("input.txt");
    fs::write(&input, "cached")?;
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Impure);
    options.set_eval_cache_enabled(true);
    let native = NixNative::with_options(0, options)?;

    assert!(
        native
            .eval_cache_snapshot()
            .expect("cache is enabled")
            .is_empty()
    );
    let source = format!(
        "builtins.readFile {}",
        nix_string_literal(&path_bytes(&input)?)?
    );
    let ir = native.lower_native_source(&source, None, None)?;
    let outcome = native.eval_ir(&ir)?;
    assert_eq!(
        outcome.heap().get_string(outcome.value())?.bytes(),
        b"cached"
    );

    let cache = native.eval_cache_snapshot().expect("cache is enabled");
    assert_eq!(cache.len(), 1);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_eval_leaves_eval_cache_absent_when_disabled() -> Result<()> {
    let root = unique_temp_dir("native-expression-eval-cache-disabled");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let input = root.join("input.txt");
    fs::write(&input, "uncached")?;
    let options = TreeWalkOptions::with_eval_mode(EvalMode::Impure);
    let native = NixNative::with_options(0, options)?;

    let source = format!(
        "builtins.readFile {}",
        nix_string_literal(&path_bytes(&input)?)?
    );
    let ir = native.lower_native_source(&source, None, None)?;
    let outcome = native.eval_ir(&ir)?;
    assert_eq!(
        outcome.heap().get_string(outcome.value())?.bytes(),
        b"uncached"
    );
    assert!(native.eval_cache_snapshot().is_none());

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_disabled_persistent_root_leaves_force_sidecars_empty() -> Result<()> {
    use crate::cache::{PersistCache, PersistParseArtifactKey};

    let root = unique_temp_dir("native-expression-persist-force-disabled");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let input = root.join("input.txt");
    let parse_root = root.join("parse");
    let persist_root = root.join("persist");
    fs::write(&input, "uncached")?;
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Impure);
    options.set_parse_cache_root(&parse_root);
    options.set_persist_cache_root(&persist_root);
    let native = NixNative::with_options(0, options)?;

    let source = format!(
        "let payload = builtins.readFile {}; in payload",
        nix_string_literal(&path_bytes(&input)?)?
    );
    let ir = native.lower_native_source(&source, None, None)?;
    let outcome = native.eval_ir(&ir)?;
    assert_eq!(
        outcome.heap().get_string(outcome.value())?.bytes(),
        b"uncached"
    );
    assert!(native.eval_cache_snapshot().is_none());

    let parse_cache = ParseCache::new(&parse_root);
    let parse_key = parse_cache.key_for_source(source.as_bytes());
    assert!(
        parse_cache.entry_for_key(parse_key).is_complete(),
        "disabled eval-cache should still allow configured parse-cache writes"
    );
    let persist = PersistCache::open(&persist_root)?;
    assert!(
        persist
            .lookup_parse_artifact(PersistParseArtifactKey::from_parse_cache_key(parse_key))?
            .is_some(),
        "disabled eval-cache should not disable configured parse persistence"
    );
    assert!(
        persist.node_metadata_index().latest_entries()?.is_empty(),
        "disabled eval-cache must not write persistent force metadata"
    );
    assert!(
        persist.node_trace_log().latest_entries()?.is_empty(),
        "disabled eval-cache must not write persistent force traces"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_parse_cache_preserves_frontend_error_spans() -> Result<()> {
    let root = unique_temp_dir("native-expression-parse-cache-error");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(root.join("parse"));
    let native = NixNative::with_options(0, options)?;

    let err = native
        .eval_expr(PARSE_ERROR_SOURCE)
        .expect_err("parse errors should fall back through the cached path");

    assert_parse_source_report(&err);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_parse_error_uses_source_report() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr(PARSE_ERROR_SOURCE)
        .expect_err("parse errors should stay fallback-eligible");

    assert_parse_source_report(&err);
    Ok(())
}

#[test]
fn native_expression_duplicate_attr_reports_multiple_labels() -> Result<()> {
    let native = NixNative::new(0)?;
    for source in ["{ a = 1; a = 2; }", "{ a.b = 1; a.b = 2; }"] {
        let err = native
            .eval_expr(source)
            .expect_err("duplicate attr paths should stay fallback-eligible");

        let Some(NativeEvalError::Unsupported {
            feature,
            span: Some(_),
        }) = err.downcast_ref::<NativeEvalError>()
        else {
            panic!("duplicate attr paths should stay unsupported fallback errors: {err:?}");
        };
        assert!(
            feature.contains("aos_nix::parse::duplicate_attribute"),
            "{feature}"
        );
        assert!(feature.contains("first definition"), "{feature}");
        assert!(feature.contains("duplicate definition"), "{feature}");
        assert!(feature.contains(source), "{feature}");
        assert!(!feature.contains("OutOfBounds"), "{feature}");
        assert!(!feature.contains("builtins.toJSON"), "{feature}");
    }
    Ok(())
}

fn assert_parse_source_report(err: &anyhow::Error) {
    let Some(NativeEvalError::Unsupported {
        feature,
        span: Some(_),
    }) = err.downcast_ref::<NativeEvalError>()
    else {
        panic!("parse errors should stay unsupported fallback errors: {err:?}");
    };
    assert!(
        feature.contains("native expression parse failure"),
        "{feature}"
    );
    assert!(feature.contains("aos_nix::parse::"), "{feature}");
    assert!(feature.contains("expr.nix"), "{feature}");
    assert!(feature.contains(PARSE_ERROR_SOURCE), "{feature}");
    assert!(!feature.contains("builtins.toJSON"), "{feature}");
}

#[test]
fn native_expression_scope_error_uses_source_report() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr("let ${name} = 1; in 1")
        .expect_err("scope errors should stay fallback-eligible");

    assert_scope_source_report(&err);
    Ok(())
}

#[test]
fn native_expression_parse_cache_preserves_scope_error_report() -> Result<()> {
    let root = unique_temp_dir("native-expression-scope-cache-error");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(root.join("parse"));
    let native = NixNative::with_options(0, options)?;

    let err = native
        .eval_expr("let ${name} = 1; in 1")
        .expect_err("scope errors should stay fallback-eligible through the cached path");

    assert_scope_source_report(&err);

    fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_scope_source_report(err: &anyhow::Error) {
    let Some(NativeEvalError::Unsupported {
        feature,
        span: Some(_),
    }) = err.downcast_ref::<NativeEvalError>()
    else {
        panic!("scope errors should stay unsupported fallback errors: {err:?}");
    };
    assert!(
        feature.contains("native expression resolve failure"),
        "{feature}"
    );
    assert!(
        feature.contains("aos_nix::resolve::dynamic_let_binding"),
        "{feature}"
    );
    assert!(feature.contains("expr.nix"), "{feature}");
    assert!(feature.contains("let ${name} = 1; in 1"), "{feature}");
    assert!(!feature.contains("builtins.toJSON"), "{feature}");
}

#[test]
fn configured_cpp_nix_native_expression_eval_matches_cli_json() -> Result<()> {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured native eval_expr check");
        return Ok(());
    };
    let native = NixNative::new(0)?;

    for source in [
        "1 + 1",
        "1 # trailing comment",
        r#""x""#,
        r#"{ b = 1; a = [ true null "x" ]; }"#,
        r#"builtins.toJSON { a = "x"; }"#,
    ] {
        let output = Command::new(&oracle)
            .args(["--eval", "--strict", "--json", "--expr", source])
            .output()?;
        assert!(
            output.status.success(),
            "C++ Nix oracle unexpectedly rejected {source:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = String::from_utf8(output.stdout)?.trim().to_string();
        assert_eq!(native.eval_expr(source)?, expected, "{source}");
    }

    Ok(())
}

#[test]
fn native_expression_eval_reports_semantic_errors() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr("1 + true")
        .expect_err("type errors are native evaluation errors");

    let Some(NativeEvalError::EvalError { message }) = err.downcast_ref::<NativeEvalError>() else {
        panic!("type error should surface as a native eval error: {err:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(message.contains("expr.nix"), "{message}");
    assert!(message.contains("1 + true"), "{message}");
    assert!(!message.contains("builtins.toJSON"), "{message}");

    for source in ["length", "currentTime"] {
        let err = native
            .eval_expr(source)
            .expect_err("unresolved globals are native evaluation errors");

        assert!(
            matches!(
                err.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::EvalError { message })
                    if message.contains("unresolved global variable")
            ),
            "{source}: {err:?}"
        );
    }
    Ok(())
}

#[test]
fn native_expression_eval_reports_caller_diagnostic_source() -> Result<()> {
    let native = NixNative::new(0)?;
    let user_expr = "1 + true";
    let prefix = "let __aos_repl_scope = {}; in with __aos_repl_scope; (";
    let expr = format!("{prefix}{user_expr})");
    let err = native
        .eval_expr_with_diagnostic_source(
            &expr,
            "repl-input.nix",
            user_expr,
            prefix.len()..prefix.len() + user_expr.len(),
        )
        .expect_err("type errors are native evaluation errors");

    let Some(NativeEvalError::EvalError { message }) = err.downcast_ref::<NativeEvalError>() else {
        panic!("type error should surface as a native eval error: {err:?}");
    };
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(message.contains("repl-input.nix"), "{message}");
    assert!(message.contains(user_expr), "{message}");
    assert!(!message.contains("builtins.toJSON"), "{message}");
    assert!(!message.contains("__aos_repl_scope"), "{message}");
    Ok(())
}

#[test]
fn native_expression_instantiation_reports_caller_diagnostic_source() -> Result<()> {
    let native = NixNative::new(0)?;
    let user_expr = "1 + true";
    let prefix = "let __aos_repl_scope = {}; in with __aos_repl_scope; (";
    let expr = format!("{prefix}{user_expr})");
    let err = native
        .instantiate_expr_with_diagnostic_source(
            &expr,
            "repl-input.nix",
            user_expr,
            prefix.len()..prefix.len() + user_expr.len(),
        )
        .expect_err("type errors are native evaluation errors");

    let Some(NativeEvalError::EvalError { message }) = err.downcast_ref::<NativeEvalError>() else {
        panic!("type error should surface as a native eval error: {err:?}");
    };
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(message.contains("repl-input.nix"), "{message}");
    assert!(message.contains(user_expr), "{message}");
    assert!(!message.contains("__aos_repl_scope"), "{message}");
    Ok(())
}

#[test]
fn native_expression_diagnostic_source_must_match_selected_range() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr_with_diagnostic_source("let x = 1; in x", "repl-input.nix", "x + 1", 14..15)
        .expect_err("mismatched diagnostic source should be rejected");

    assert!(
        matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Internal { message })
                if message.contains("diagnostic source does not match")
        ),
        "{err:?}"
    );
    Ok(())
}

#[test]
fn native_expression_type_error_reports_operand_labels() -> Result<()> {
    let native = NixNative::new(0)?;
    for source in ["1 + \"x\"", "1 > \"x\"", "1 <= \"x\""] {
        let err = native
            .eval_expr(source)
            .expect_err("type errors are native evaluation errors");

        let Some(NativeEvalError::EvalError { message }) = err.downcast_ref::<NativeEvalError>()
        else {
            panic!("type error should surface as a native eval error: {err:?}");
        };
        assert!(message.contains("aos_nix::eval::type"), "{message}");
        assert!(message.contains("left operand"), "{message}");
        assert!(message.contains("right operand"), "{message}");
        assert!(message.contains(source), "{message}");
        assert!(!message.contains("builtins.toJSON"), "{message}");
        assert!(!message.contains("OutOfBounds"), "{message}");
    }

    Ok(())
}

#[test]
fn native_expression_type_error_reports_add_error_context_labels() -> Result<()> {
    let native = NixNative::new(0)?;
    let source = r#"builtins.addErrorContext "ctx" (1 + true)"#;
    let err = native
        .eval_expr(source)
        .expect_err("type errors with logical context are native evaluation errors");

    let Some(NativeEvalError::EvalError { message }) = err.downcast_ref::<NativeEvalError>() else {
        panic!("type error should surface as a native eval error: {err:?}");
    };
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(message.contains("while evaluating: ctx"), "{message}");
    assert!(message.contains(source), "{message}");
    assert!(!message.contains("builtins.toJSON"), "{message}");
    Ok(())
}

#[test]
fn native_expression_eval_summarizes_and_expands_logical_traces_by_verbosity() -> Result<()> {
    let source = r#"
        builtins.addErrorContext "one" (
          builtins.addErrorContext "two" (
            builtins.addErrorContext "three" (
              builtins.addErrorContext "four" (builtins.throw "boom")
            )
          )
        )
    "#;

    let summary_err = NixNative::new(0)?
        .eval_expr(source)
        .expect_err("throw should render a summarized native trace");
    let Some(NativeEvalError::EvalError { message: summary }) =
        summary_err.downcast_ref::<NativeEvalError>()
    else {
        panic!("throw should surface as a native eval error: {summary_err:?}");
    };
    let summary_trace = summary
        .split("Evaluation trace:")
        .nth(1)
        .expect("summary diagnostic should include an appended trace");
    assert!(
        summary_trace.contains("while evaluating: one at expr.nix:"),
        "{summary}"
    );
    assert!(summary_trace.contains("1 more frame hidden"), "{summary}");
    assert!(
        !summary_trace.contains("while evaluating: four"),
        "{summary}"
    );

    let full_err = NixNative::new(1)?
        .eval_expr(source)
        .expect_err("throw should render a full native trace");
    let Some(NativeEvalError::EvalError { message: full }) =
        full_err.downcast_ref::<NativeEvalError>()
    else {
        panic!("throw should surface as a native eval error: {full_err:?}");
    };
    let full_trace = full
        .split("Evaluation trace:")
        .nth(1)
        .expect("full diagnostic should include an appended trace");
    assert!(
        full_trace.contains("while evaluating: four at expr.nix:"),
        "{full}"
    );
    assert!(!full_trace.contains("hidden"), "{full}");
    Ok(())
}

#[test]
fn native_expression_import_error_does_not_attribute_root_trace_context_to_child_source()
-> Result<()> {
    let root = unique_temp_dir("native-expression-imported-trace-source");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let child = root.join("child.nix");
    let child_source = format!(r#"let padding = "{}"; in 1 + true"#, "a".repeat(256));
    fs::write(&child, child_source.as_bytes())?;
    let expr = format!(
        r#"builtins.addErrorContext "root context" (import {})"#,
        child.to_string_lossy()
    );
    let source = json_wrapper_source(&expr);
    let source_map = WrappedSourceMap {
        prefix_len: JSON_WRAPPER_PREFIX.len(),
        expr_len: expr.len(),
    };
    let diagnostic_source = NativeDiagnosticSource::new("expr.nix", &expr, Some(source_map));
    let native = NixNative::new(1)?;
    let ir = native.lower_native_source(&source, Some(source_map), Some(diagnostic_source))?;
    let error = native
        .eval_ir(&ir)
        .expect_err("imported child type error should fail native evaluation");
    let native_error =
        native_eval_error_with_source_trace(error, diagnostic_source, EvalTraceStyle::Full);

    let NativeEvalError::EvalError { message } = native_error else {
        panic!("imported child type error should surface as native eval error");
    };
    let trace = message
        .split("Evaluation trace:")
        .nth(1)
        .expect("diagnostic should include an appended trace");
    assert!(
        trace.contains("while evaluating: root context"),
        "{message}"
    );
    assert!(
        !trace.contains(&format!(
            "while evaluating: root context at {}",
            child.to_string_lossy()
        )),
        "{message}"
    );
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_json_preflight_ignores_malformed_empty_builtins_attr_paths() {
    use crate::compile::{IrArena, IrInlineCacheSiteId, IrNode};
    use crate::syntax::SymbolTable;

    let mut symbols = SymbolTable::new();
    let builtins = symbols.intern(b"builtins").expect("symbol interns");
    let ir = Ir {
        root: IrId::new(1),
        arena: IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::GlobalVar,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::GlobalVar {
                        site: IrInlineCacheSiteId::new(0),
                        symbol: builtins,
                    },
                ),
                IrNode::new(
                    IrKind::Select,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::Select {
                        site: IrInlineCacheSiteId::new(0),
                        receiver: IrId::new(0),
                        path: IrAttrPathId::new(0),
                        default: None,
                    },
                ),
            ],
            Vec::new(),
        ),
        facts: IrFacts::conservative(2),
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: vec![Vec::<IrAttrPathSegment>::new().into_boxed_slice()].into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };

    assert_eq!(
        builtins_global_native_json_fallback_feature(&ir, 0, &TreeWalkOptions::new()),
        None
    );
}

#[test]
fn native_expression_eval_rejects_cli_sensitive_builtins() -> Result<()> {
    let native = NixNative::new(0)?;

    for source in [
        r#"builtins.getEnv "HOME""#,
        "builtins.nixPath",
        "builtins.builtins",
        "builtins.currentTime",
        "builtins ? currentSystem",
        "builtins.attrNames builtins",
        "builtins.fetchMercurial",
        "<nixpkgs>",
        r#"derivation { name = "x"; system = "x86_64-linux"; builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder"; }"#,
        r#"builtins.derivation { name = "x"; system = "x86_64-linux"; builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder"; }"#,
    ] {
        let err = native
            .eval_expr(source)
            .expect_err("CLI-sensitive expressions must fall back");
        assert!(
            matches!(
                err.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { span: Some(_), .. })
            ),
            "{source}"
        );
    }

    Ok(())
}

#[test]
fn native_expression_eval_reports_flakes_as_the_fallback_feature() -> Result<()> {
    let native = NixNative::new(0)?;

    for source in [
        r#"builtins.getFlake "github:NixOS/nixpkgs/0000000000000000000000000000000000000000""#,
        "builtins.getFlake or null",
    ] {
        let err = native
            .eval_expr(source)
            .expect_err("flake expressions must fall back");
        assert!(
            matches!(
                err.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                    if feature == "flakes"
            ),
            "{source}: {err:?}"
        );
    }

    Ok(())
}

#[test]
fn native_expression_eval_supports_pure_flake_ref_helpers() -> Result<()> {
    let native = NixNative::new(0)?;

    assert_eq!(
        native.eval_expr(r#"builtins.parseFlakeRef "github:NixOS/nixpkgs/23.05?dir=lib""#)?,
        r#"{"dir":"lib","owner":"NixOS","ref":"23.05","repo":"nixpkgs","type":"github"}"#
    );
    assert_eq!(
        native.eval_expr(r#"let parse = builtins.parseFlakeRef; in parse "nixpkgs/unstable""#)?,
        r#"{"id":"nixpkgs","ref":"unstable","type":"indirect"}"#
    );
    assert_eq!(
        native.eval_expr(
            r#"let b = { inherit (builtins) parseFlakeRef; }; in b.parseFlakeRef "nixpkgs/unstable""#
        )?,
        r#"{"id":"nixpkgs","ref":"unstable","type":"indirect"}"#
    );
    assert_eq!(
        native.eval_expr(
            r#"let render = builtins.flakeRefToString; in render {
                dir = "lib";
                owner = "NixOS";
                ref = "23.05";
                repo = "nixpkgs";
                type = "github";
            }"#
        )?,
        r#""github:NixOS/nixpkgs/23.05?dir=lib""#
    );
    assert_eq!(
        native.eval_expr(
            r#"let b = { inherit (builtins) flakeRefToString; }; in b.flakeRefToString {
                type = "indirect";
                id = "nixpkgs";
            }"#
        )?,
        r#""flake:nixpkgs""#
    );

    Ok(())
}

#[test]
fn native_expression_eval_uses_configured_current_system_and_time() -> Result<()> {
    let native = NixNative::with_options(
        0,
        TreeWalkOptions::with_current_system(b"aos-test-target".to_vec())?,
    )?;

    assert_eq!(
        native.eval_expr("builtins.currentSystem")?,
        "\"aos-test-target\""
    );
    assert_eq!(
        native.eval_expr(r#"builtins.currentSystem or "fallback""#)?,
        "\"aos-test-target\""
    );

    let native = NixNative::with_options(0, TreeWalkOptions::with_current_time(1_700_000_000)?)?;
    assert_eq!(native.eval_expr("builtins.currentTime")?, "1700000000");
    assert_eq!(
        native.eval_expr("builtins.currentTime or 42")?,
        "1700000000"
    );
    Ok(())
}

#[test]
fn configured_native_expression_eval_still_rejects_reified_builtins_inventory() -> Result<()> {
    let native = NixNative::with_options(
        0,
        TreeWalkOptions::with_current_system(b"aos-test-target".to_vec())?,
    )?;

    let err = native
        .eval_expr("builtins.attrNames builtins")
        .expect_err("reified builtins inventory should still fall back");
    assert!(
        matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { span: Some(_), .. })
        ),
        "{err:?}"
    );
    Ok(())
}

#[test]
fn native_expression_eval_supports_legacy_let_attrsets() -> Result<()> {
    let native = NixNative::new(0)?;
    assert_eq!(native.eval_expr("let { body = 1; }")?, "1");
    assert_eq!(native.eval_expr("let { x = 1; body = x + 1; }")?, "2");
    assert_eq!(native.eval_expr("let { body.foo = 1; }")?, r#"{"foo":1}"#);
    assert_eq!(
        native.eval_expr(r#"let { "${"body"}" = "interp"; }"#)?,
        r#""interp""#
    );
    assert_eq!(
        native.eval_expr(r#"let { name = "body"; ${name} = "dynamic"; }"#)?,
        r#""dynamic""#
    );
    assert_eq!(native.eval_expr(r#"let { "body" = "ok"; }"#)?, r#""ok""#);
    Ok(())
}

#[test]
fn native_expression_eval_handles_functor_application() -> Result<()> {
    let native = NixNative::new(0)?;
    let json = native.eval_expr("({ __functor = self: x: x + 1; } 1)")?;

    assert_eq!(json, "2");
    Ok(())
}

#[test]
fn native_expression_eval_keeps_non_functor_attrset_application_fallback_eligible() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr("({} 1)")
        .expect_err("non-functor attrset application should fall back to the CLI");

    assert!(matches!(
        err.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::Unsupported { feature, span: Some(_) })
            if feature.contains("type error")
    ));
    Ok(())
}

#[test]
fn native_expression_eval_reports_missing_import_as_eval_error() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr(r#"import "/tmp/aos-nix-native-missing-import.nix""#)
        .expect_err("missing imports should report native eval errors");

    assert!(matches!(
        err.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::EvalError { .. })
    ));
    assert_eq!(native.name(), "aos-nix");
    Ok(())
}
