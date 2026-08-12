//! Tests for semantic no-op native source edits at the `.drv` closure boundary.

use super::*;
use crate::cache::{
    CachedExpressionValue, ParseCache, ParseFileKey, PersistCache, PersistParseArtifactKey,
};

#[test]
fn native_instantiation_expr_comment_only_edit_preserves_drv_closure() -> Result<()> {
    let root = unique_temp_dir("native-instantiation-raw-semantic-edit");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let first_parse_root = root.join("first-parse");
    let second_parse_root = root.join("second-parse");
    let third_parse_root = root.join("third-parse");
    let persist_root = root.join("persist");
    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let first_expr = r#"# first raw wrapper comment
       let
         base = derivationStrict {
           name = "raw-semantic-edit-base";
           system = "x86_64-linux";
           builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           env = "stable";
         };
       in derivationStrict {
         name = "raw-semantic-edit-consumer";
         system = "x86_64-linux";
         builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
         input = "${base.out}";
       }"#;
    let second_expr = r#"
       # changed raw wrapper comment and whitespace

       let
         base = derivationStrict {
           name = "raw-semantic-edit-base";
           system = "x86_64-linux";
           builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           env = "stable";
         };
       in derivationStrict {
         name = "raw-semantic-edit-consumer";
         system = "x86_64-linux";
         builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
         input = "${base.out}";
       }"#;
    let first_source = derivation_path_wrapper_source(first_expr);
    let second_source = derivation_path_wrapper_source(second_expr);

    let uncached_first_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    let uncached_first =
        NixNative::with_options(0, uncached_first_options)?.instantiate_expr_closure(first_expr)?;
    assert_eq!(uncached_first.drvs().len(), 2);

    let mut cached_first_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    cached_first_options.set_parse_cache_root(&first_parse_root);
    cached_first_options.set_persist_cache_root(&persist_root);
    cached_first_options.set_eval_cache_enabled(true);
    let cached_first =
        NixNative::with_options(0, cached_first_options)?.instantiate_expr_closure(first_expr)?;
    assert_eq!(cached_first, uncached_first);
    let first_parse_cache = ParseCache::new(&first_parse_root);
    let first_parse_key = first_parse_cache.key_for_source(first_source.as_bytes());
    assert!(
        first_parse_cache
            .entry_for_key(first_parse_key)
            .is_complete()
    );
    assert!(
        PersistCache::open(&persist_root)?
            .lookup_parse_artifact(PersistParseArtifactKey::from_parse_cache_key(
                first_parse_key
            ))?
            .is_some(),
        "first raw expression should write a durable parse artifact"
    );

    let uncached_second_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    let uncached_second = NixNative::with_options(0, uncached_second_options)?
        .instantiate_expr_closure(second_expr)?;
    assert_eq!(uncached_second, uncached_first);

    let observed_second_hits = Arc::new(Mutex::new(Vec::new()));
    let observed_second_hits_for_hook = Arc::clone(&observed_second_hits);
    let mut cached_second_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    cached_second_options.set_parse_cache_root(&second_parse_root);
    cached_second_options.set_persist_cache_root(&persist_root);
    cached_second_options.set_eval_cache_enabled(true);
    let mut cached_second_native = NixNative::with_options(0, cached_second_options)?;
    cached_second_native.set_persistent_parse_hit_hook(move |hit| {
        observed_second_hits_for_hook
            .lock()
            .expect("persistent parse hit observations lock")
            .push(hit);
    });
    let cached_second = cached_second_native.instantiate_expr_closure(second_expr)?;
    assert_eq!(cached_second, uncached_first);
    assert!(
        observed_second_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .is_empty(),
        "changed raw source should miss the first parse artifact"
    );
    let second_parse_cache = ParseCache::new(&second_parse_root);
    let second_parse_key = second_parse_cache.key_for_source(second_source.as_bytes());
    assert!(
        second_parse_cache
            .entry_for_key(second_parse_key)
            .is_complete()
    );
    assert!(
        PersistCache::open(&persist_root)?
            .lookup_parse_artifact(PersistParseArtifactKey::from_parse_cache_key(
                second_parse_key
            ))?
            .is_some(),
        "changed raw expression should write its own durable parse artifact"
    );

    let observed_third_hits = Arc::new(Mutex::new(Vec::new()));
    let observed_third_hits_for_hook = Arc::clone(&observed_third_hits);
    let mut hit_options = TreeWalkOptions::with_store_dir(store_bytes)?;
    hit_options.set_parse_cache_root(&third_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    hit_options.set_eval_cache_enabled(true);
    let mut hit_native = NixNative::with_options(0, hit_options)?;
    hit_native.set_persistent_parse_hit_hook(move |hit| {
        observed_third_hits_for_hook
            .lock()
            .expect("persistent parse hit observations lock")
            .push(hit);
    });
    let changed_hit = hit_native.instantiate_expr_closure(second_expr)?;
    assert_eq!(changed_hit, uncached_first);
    assert_eq!(
        observed_third_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .clone(),
        vec![NativePersistentParseHit::Bytes]
    );
    assert!(
        ParseCache::new(&third_parse_root)
            .entry_for_key(second_parse_key)
            .is_complete(),
        "persistent changed raw parse hit should hydrate the fresh parse-cache entry"
    );

    let mut canaries = durable_hash_surface_canaries(
        "initial raw comment parse-cache BLAKE3",
        first_parse_key.as_durable_hash(),
    );
    canaries.extend(durable_hash_surface_canaries(
        "changed raw comment parse-cache BLAKE3",
        second_parse_key.as_durable_hash(),
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached initial raw semantic-edit closure",
        &uncached_first,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cached initial raw semantic-edit closure",
        &cached_first,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached changed raw semantic-edit closure",
        &uncached_second,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cached changed raw semantic-edit closure",
        &cached_second,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit changed raw semantic-edit closure",
        &changed_hit,
        &canaries,
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_comment_only_forced_leaf_edit_preserves_drv_closure() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-instantiate-forced-semantic-edit");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let first_parse_root = root.join("first-parse");
    let first_hit_parse_root = root.join("first-hit-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    let leaf = dir.join("leaf.nix");
    fs::write(
        &file,
        r#"let
          stable = let b = builtins; in { system = b.currentSystem; };
          leaf = import ./leaf.nix stable;
          base = derivationStrict {
            name = "forced-semantic-edit-base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [ leaf.system ];
          };
        in {
          pkgs.hello = derivationStrict {
            name = "forced-semantic-edit-consumer";
            system = "x86_64-linux";
            builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
            input = "${base.out}";
          };
        }"#,
    )?;
    let first_leaf_source = b"# first forced leaf comment\nstable: stable\n";
    let second_leaf_source = b"\n# changed forced leaf comment with whitespace\n\nstable: stable\n";
    fs::write(&leaf, first_leaf_source)?;
    let leaf_realpath = fs::canonicalize(&leaf)?;
    let store_bytes = store.as_os_str().as_bytes().to_vec();

    let uncached_options = || -> Result<TreeWalkOptions> {
        let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
        options.set_store_dir(store_bytes.clone())?;
        Ok(options)
    };
    let cached_options = |parse_root: &Path| -> Result<TreeWalkOptions> {
        let mut options = uncached_options()?;
        options.set_parse_cache_root(parse_root);
        options.set_persist_cache_root(&persist_root);
        options.set_eval_cache_enabled(true);
        Ok(options)
    };

    let (uncached_first, uncached_first_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, uncached_options()?)?,
        &file,
        "pkgs.hello",
    )?;
    assert_eq!(uncached_first_stats.force_cache_hits(), 0);
    assert_eq!(uncached_first_stats.force_cache_misses(), 0);
    assert_eq!(uncached_first.drvs().len(), 2);

    let (first_cached, first_cached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, cached_options(&first_parse_root)?)?,
        &file,
        "pkgs.hello",
    )?;
    assert_eq!(first_cached, uncached_first);
    assert_eq!(first_cached_stats.force_cache_hits(), 0);
    assert_eq!(first_cached_stats.derivation_aterm_path_reuses(), 0);
    assert_eq!(first_cached_stats.static_derivation_output_path_reuses(), 0);
    assert!(first_cached_stats.derivation_hash_calculations() > 0);
    assert!(first_cached_stats.derivation_text_path_calculations() > 0);
    assert!(
        first_cached_stats.force_cache_misses() > 0,
        "first forced leaf run should miss before recording demand"
    );

    let (first_materialized, first_materialized_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, cached_options(&first_parse_root)?)?,
        &file,
        "pkgs.hello",
    )?;
    assert_eq!(first_materialized, uncached_first);
    assert_eq!(first_materialized_stats.force_cache_hits(), 0);
    assert_eq!(first_materialized_stats.derivation_aterm_path_reuses(), 2);
    assert_eq!(
        first_materialized_stats.static_derivation_output_path_reuses(),
        2
    );
    assert_eq!(first_materialized_stats.derivation_hash_calculations(), 0);
    assert_eq!(
        first_materialized_stats.derivation_text_path_calculations(),
        0
    );
    assert!(
        first_materialized_stats.force_cache_misses() > 0,
        "second forced leaf run should miss before materializing a persistent payload"
    );

    let first_parse_cache = ParseCache::new(&first_parse_root);
    let first_parse_key = first_parse_cache.key_for_source(first_leaf_source);
    assert!(
        first_parse_cache
            .entry_for_source(first_leaf_source)
            .is_complete(),
        "initial forced leaf should be parsed into the first cache root"
    );
    let first_force_canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    assert_persistent_context_free_string_force_cache_payload(
        &persist_root,
        b"x86_64-linux",
        "initial forced leaf currentSystem",
    )?;

    let (first_hit, first_hit_stats, first_hit_keys) =
        instantiate_file_closure_with_stats_and_hits(
            &NixNative::with_options(0, cached_options(&first_hit_parse_root)?)?,
            &file,
            "pkgs.hello",
        )?;
    assert_eq!(first_hit, uncached_first);
    assert!(
        first_hit_stats.force_cache_hits() > 0,
        "same-source fresh runtime should load a persistent force-cache payload"
    );
    assert!(
        !first_hit_keys.is_empty(),
        "same-source fresh runtime should report persistent force-cache hit keys"
    );
    assert_eq!(
        first_hit_stats.force_cache_hits(),
        first_hit_keys.len() as u64,
        "same-source fresh runtime should account for persistent force-cache hits"
    );
    assert_persistent_force_cache_hit_keys_decode(
        &persist_root,
        &first_hit_keys,
        "same-source fresh runtime",
    )?;
    assert_eq!(first_hit_stats.derivation_aterm_path_reuses(), 2);
    assert_eq!(first_hit_stats.static_derivation_output_path_reuses(), 2);
    assert_eq!(first_hit_stats.derivation_hash_calculations(), 0);
    assert_eq!(first_hit_stats.derivation_text_path_calculations(), 0);

    fs::write(&leaf, second_leaf_source)?;

    let (uncached_second, uncached_second_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, uncached_options()?)?,
        &file,
        "pkgs.hello",
    )?;
    assert_eq!(uncached_second_stats.force_cache_hits(), 0);
    assert_eq!(uncached_second_stats.force_cache_misses(), 0);
    assert_eq!(uncached_second, uncached_first);

    let observed_hits = Arc::new(Mutex::new(Vec::new()));
    let observed_hits_for_hook = Arc::clone(&observed_hits);
    let mut changed_native = NixNative::with_options(0, cached_options(&second_parse_root)?)?;
    changed_native.set_persistent_parse_hit_hook(move |hit| {
        observed_hits_for_hook
            .lock()
            .expect("persistent parse hit observations lock")
            .push(hit);
    });
    let (cached_second, cached_second_stats, cached_second_hit_keys) =
        instantiate_file_closure_with_stats_and_hits(&changed_native, &file, "pkgs.hello")?;

    assert_eq!(cached_second, uncached_first);
    assert!(
        cached_second_stats.force_cache_hits() > 0,
        "comment-only forced leaf edit should reuse the dependency's semantic force-cache payload"
    );
    assert_eq!(
        cached_second_stats.force_cache_hits(),
        cached_second_hit_keys.len() as u64,
        "comment-only forced leaf edit should account for its dependency-granular cache hits"
    );
    assert_persistent_force_cache_hit_keys_decode(
        &persist_root,
        &cached_second_hit_keys,
        "comment-only forced leaf edit",
    )?;
    assert_eq!(
        cached_second_stats.force_cache_misses(),
        0,
        "transparent changed source boundary should not manufacture forced-expression misses"
    );
    assert_eq!(cached_second_stats.derivation_aterm_path_reuses(), 2);
    assert_eq!(
        cached_second_stats.static_derivation_output_path_reuses(),
        2
    );
    assert_eq!(cached_second_stats.derivation_hash_calculations(), 0);
    assert_eq!(cached_second_stats.derivation_text_path_calculations(), 0);
    assert_eq!(
        observed_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .clone(),
        vec![NativePersistentParseHit::Source]
    );
    let second_parse_cache = ParseCache::new(&second_parse_root);
    let second_parse_key = second_parse_cache.key_for_source(second_leaf_source);
    assert!(
        second_parse_cache
            .entry_for_source(second_leaf_source)
            .is_complete(),
        "changed forced leaf should be reparsed into the fresh cache root"
    );
    let (changed_hit, changed_hit_stats, changed_hit_keys) =
        instantiate_file_closure_with_stats_and_hits(
            &NixNative::with_options(0, cached_options(&second_parse_root)?)?,
            &file,
            "pkgs.hello",
        )?;
    assert_eq!(changed_hit, uncached_first);
    assert!(
        changed_hit_stats.force_cache_hits() > 0,
        "second changed-source run should load a persistent force-cache payload"
    );
    assert!(
        !changed_hit_keys.is_empty(),
        "second changed-source run should report persistent force-cache hit keys"
    );
    assert_eq!(
        changed_hit_stats.force_cache_hits(),
        changed_hit_keys.len() as u64,
        "second changed-source run should account for persistent force-cache hits"
    );
    assert_persistent_force_cache_hit_keys_decode(
        &persist_root,
        &changed_hit_keys,
        "second changed-source run",
    )?;
    assert_eq!(changed_hit_stats.derivation_aterm_path_reuses(), 2);
    assert_eq!(changed_hit_stats.static_derivation_output_path_reuses(), 2);
    assert_eq!(changed_hit_stats.derivation_hash_calculations(), 0);
    assert_eq!(changed_hit_stats.derivation_text_path_calculations(), 0);

    let first_leaf_key = ParseFileKey::for_source(&leaf_realpath, first_leaf_source);
    let second_leaf_key = ParseFileKey::for_source(&leaf_realpath, second_leaf_source);
    let mut canaries = persistent_force_cache_surface_canaries(&persist_root)?;
    canaries.extend(first_force_canaries);
    canaries.extend(durable_hash_surface_canaries(
        "initial forced comment leaf parse-cache BLAKE3",
        first_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "changed forced comment leaf parse-cache BLAKE3",
        second_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "initial forced comment leaf content BLAKE3",
        first_leaf_key.content_hash().as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "changed forced comment leaf content BLAKE3",
        second_leaf_key.content_hash().as_durable_hash(),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "forced leaf currentSystem hot xxh3",
        context_free_nix_string_xxh3(b"x86_64-linux"),
    ));

    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached initial forced semantic-edit closure",
        &uncached_first,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cached initial forced semantic-edit closure",
        &first_cached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "materialized initial forced semantic-edit closure",
        &first_materialized,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit initial forced semantic-edit closure",
        &first_hit,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached changed forced semantic-edit closure",
        &uncached_second,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cached changed forced semantic-edit closure",
        &cached_second,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit changed forced semantic-edit closure",
        &changed_hit,
        &canaries,
    );

    Ok(())
}

fn assert_persistent_context_free_string_force_cache_payload(
    persist_root: &Path,
    bytes: &[u8],
    context: &str,
) -> Result<()> {
    let value_hash = CachedExpressionValue::context_free_string(bytes.to_vec()).value_hash()?;
    let persist = PersistCache::open(persist_root)?;
    let mut found = false;
    for entry in persist.node_metadata_index().latest_entries()? {
        if entry.value().materialized_value_hash() != Some(value_hash) {
            continue;
        }
        let value = persist
            .load_cached_expression_node_value_indexed(entry.key())?
            .unwrap_or_else(|| {
                panic!("{context} force-cache metadata should point at an indexed payload")
            });
        assert_eq!(
            value.context_free_string_bytes(),
            Some(bytes),
            "{context} force-cache payload should decode to the expected context-free string"
        );
        found = true;
    }
    assert!(
        found,
        "{context} should have at least one materialized force-cache key"
    );
    Ok(())
}

fn assert_persistent_force_cache_hit_keys_decode(
    persist_root: &Path,
    keys: &[PersistNodeMetadataKey],
    context: &str,
) -> Result<()> {
    let persist = PersistCache::open(persist_root)?;
    for key in keys {
        assert!(
            persist
                .load_cached_expression_node_value_indexed(*key)?
                .is_some(),
            "{context} force-cache hit key should decode through the persistent payload index"
        );
    }
    Ok(())
}

#[test]
fn native_file_instantiation_comment_only_leaf_edit_preserves_drv_closure() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-instantiate-semantic-edit");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let first_parse_root = root.join("first-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    let leaf = dir.join("leaf.nix");
    fs::write(
        &file,
        r#"let
          leaf = import ./leaf.nix;
          base = derivationStrict {
            name = "semantic-edit-base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = leaf;
          };
        in {
          pkgs.hello = derivationStrict {
            name = "semantic-edit-consumer";
            system = "x86_64-linux";
            builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
            input = "${base.out}";
          };
        }"#,
    )?;
    let first_leaf_source = b"# first comment\n\"leaf-value\"\n";
    let second_leaf_source = b"\n# changed comment with extra whitespace\n\n\"leaf-value\"\n";
    fs::write(&leaf, first_leaf_source)?;
    let leaf_realpath = fs::canonicalize(&leaf)?;
    let store_bytes = store.as_os_str().as_bytes().to_vec();

    let uncached_first_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    let uncached_first = NixNative::with_options(0, uncached_first_options)?
        .instantiate_closure(&file, "pkgs.hello")?;
    assert_eq!(uncached_first.drvs().len(), 2);

    let mut cached_first_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    cached_first_options.set_parse_cache_root(&first_parse_root);
    cached_first_options.set_persist_cache_root(&persist_root);
    cached_first_options.set_eval_cache_enabled(true);
    let cached_first = NixNative::with_options(0, cached_first_options)?
        .instantiate_closure(&file, "pkgs.hello")?;
    assert_eq!(cached_first, uncached_first);
    let first_parse_cache = ParseCache::new(&first_parse_root);
    let first_parse_key = first_parse_cache.key_for_source(first_leaf_source);
    assert!(
        first_parse_cache
            .entry_for_source(first_leaf_source)
            .is_complete(),
        "initial leaf should be parsed into the first cache root"
    );

    fs::write(&leaf, second_leaf_source)?;

    let uncached_second_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    let uncached_second = NixNative::with_options(0, uncached_second_options)?
        .instantiate_closure(&file, "pkgs.hello")?;
    assert_eq!(uncached_second, uncached_first);

    let observed_hits = Arc::new(Mutex::new(Vec::new()));
    let observed_hits_for_hook = Arc::clone(&observed_hits);
    let mut cached_second_options = TreeWalkOptions::with_store_dir(store_bytes)?;
    cached_second_options.set_parse_cache_root(&second_parse_root);
    cached_second_options.set_persist_cache_root(&persist_root);
    cached_second_options.set_eval_cache_enabled(true);
    let mut cached_second_native = NixNative::with_options(0, cached_second_options)?;
    cached_second_native.set_persistent_parse_hit_hook(move |hit| {
        observed_hits_for_hook
            .lock()
            .expect("persistent parse hit observations lock")
            .push(hit);
    });
    let (cached_second, cached_second_stats) =
        instantiate_file_closure_with_stats(&cached_second_native, &file, "pkgs.hello")?;

    assert_eq!(cached_second, uncached_first);
    assert_eq!(cached_second_stats.derivation_aterm_path_reuses(), 2);
    assert_eq!(
        cached_second_stats.static_derivation_output_path_reuses(),
        2
    );
    assert_eq!(cached_second_stats.derivation_hash_calculations(), 0);
    assert_eq!(cached_second_stats.derivation_text_path_calculations(), 0);
    assert_eq!(
        observed_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .clone(),
        vec![NativePersistentParseHit::Source]
    );
    let second_parse_cache = ParseCache::new(&second_parse_root);
    let second_parse_key = second_parse_cache.key_for_source(second_leaf_source);
    assert!(
        second_parse_cache
            .entry_for_source(second_leaf_source)
            .is_complete(),
        "changed leaf should be reparsed into the fresh cache root"
    );

    let first_leaf_key = ParseFileKey::for_source(&leaf_realpath, first_leaf_source);
    let second_leaf_key = ParseFileKey::for_source(&leaf_realpath, second_leaf_source);
    let mut canaries = durable_hash_surface_canaries(
        "initial comment leaf parse-cache BLAKE3",
        first_parse_key.as_durable_hash(),
    );
    canaries.extend(durable_hash_surface_canaries(
        "changed comment leaf parse-cache BLAKE3",
        second_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "initial comment leaf content BLAKE3",
        first_leaf_key.content_hash().as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "changed comment leaf content BLAKE3",
        second_leaf_key.content_hash().as_durable_hash(),
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached initial semantic-edit closure",
        &uncached_first,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cached initial semantic-edit closure",
        &cached_first,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached changed semantic-edit closure",
        &uncached_second,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cached changed semantic-edit closure",
        &cached_second,
        &canaries,
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_unused_leaf_package_edit_preserves_drv_closure() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-instantiate-unused-leaf-edit");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let first_parse_root = root.join("first-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    let leaf = dir.join("leaf.nix");
    fs::write(
        &file,
        r#"let
          leaf = import ./leaf.nix;
          base = derivationStrict {
            name = "unused-leaf-edit-base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = leaf.used;
          };
        in {
          pkgs.hello = derivationStrict {
            name = "unused-leaf-edit-consumer";
            system = "x86_64-linux";
            builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
            input = "${base.out}";
          };
        }"#,
    )?;
    let first_leaf_source = br#"{
  used = "leaf-value";
  unused = derivationStrict {
    name = "unused-one";
    system = "x86_64-linux";
    builder = "/nix/store/cccccccccccccccccccccccccccccccc-builder";
  };
}
"#;
    let second_leaf_source = br#"{
  used = "leaf-value";
  unused = derivationStrict {
    name = "unused-two";
    system = "x86_64-linux";
    builder = "/nix/store/dddddddddddddddddddddddddddddddd-builder";
  };
}
"#;
    fs::write(&leaf, first_leaf_source)?;
    let leaf_realpath = fs::canonicalize(&leaf)?;
    let store_bytes = store.as_os_str().as_bytes().to_vec();

    let uncached_first_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    let uncached_first = NixNative::with_options(0, uncached_first_options)?
        .instantiate_closure(&file, "pkgs.hello")?;
    assert_eq!(uncached_first.drvs().len(), 2);

    let mut cached_first_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    cached_first_options.set_parse_cache_root(&first_parse_root);
    cached_first_options.set_persist_cache_root(&persist_root);
    cached_first_options.set_eval_cache_enabled(true);
    let cached_first = NixNative::with_options(0, cached_first_options)?
        .instantiate_closure(&file, "pkgs.hello")?;
    assert_eq!(cached_first, uncached_first);
    let first_parse_cache = ParseCache::new(&first_parse_root);
    let first_parse_key = first_parse_cache.key_for_source(first_leaf_source);
    assert!(
        first_parse_cache
            .entry_for_source(first_leaf_source)
            .is_complete(),
        "initial leaf package should be parsed into the first cache root"
    );

    fs::write(&leaf, second_leaf_source)?;

    let uncached_second_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    let uncached_second = NixNative::with_options(0, uncached_second_options)?
        .instantiate_closure(&file, "pkgs.hello")?;
    assert_eq!(uncached_second, uncached_first);

    let observed_hits = Arc::new(Mutex::new(Vec::new()));
    let observed_hits_for_hook = Arc::clone(&observed_hits);
    let mut cached_second_options = TreeWalkOptions::with_store_dir(store_bytes)?;
    cached_second_options.set_parse_cache_root(&second_parse_root);
    cached_second_options.set_persist_cache_root(&persist_root);
    cached_second_options.set_eval_cache_enabled(true);
    let mut cached_second_native = NixNative::with_options(0, cached_second_options)?;
    cached_second_native.set_persistent_parse_hit_hook(move |hit| {
        observed_hits_for_hook
            .lock()
            .expect("persistent parse hit observations lock")
            .push(hit);
    });
    let (cached_second, cached_second_stats) =
        instantiate_file_closure_with_stats(&cached_second_native, &file, "pkgs.hello")?;

    assert_eq!(cached_second, uncached_first);
    assert_eq!(cached_second_stats.derivation_aterm_path_reuses(), 2);
    assert_eq!(
        cached_second_stats.static_derivation_output_path_reuses(),
        2
    );
    assert_eq!(cached_second_stats.derivation_hash_calculations(), 0);
    assert_eq!(cached_second_stats.derivation_text_path_calculations(), 0);
    assert_eq!(
        observed_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .clone(),
        vec![NativePersistentParseHit::Source]
    );
    let second_parse_cache = ParseCache::new(&second_parse_root);
    let second_parse_key = second_parse_cache.key_for_source(second_leaf_source);
    assert!(
        second_parse_cache
            .entry_for_source(second_leaf_source)
            .is_complete(),
        "changed leaf package should be reparsed into the fresh cache root"
    );

    let first_leaf_key = ParseFileKey::for_source(&leaf_realpath, first_leaf_source);
    let second_leaf_key = ParseFileKey::for_source(&leaf_realpath, second_leaf_source);
    let mut canaries = durable_hash_surface_canaries(
        "initial unused leaf parse-cache BLAKE3",
        first_parse_key.as_durable_hash(),
    );
    canaries.extend(durable_hash_surface_canaries(
        "changed unused leaf parse-cache BLAKE3",
        second_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "initial unused leaf content BLAKE3",
        first_leaf_key.content_hash().as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "changed unused leaf content BLAKE3",
        second_leaf_key.content_hash().as_durable_hash(),
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached initial unused-leaf closure",
        &uncached_first,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cached initial unused-leaf closure",
        &cached_first,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached changed unused-leaf closure",
        &uncached_second,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cached changed unused-leaf closure",
        &cached_second,
        &canaries,
    );

    fs::remove_dir_all(root)?;
    Ok(())
}
