//! Tests for raw-expression instantiation, in-memory `.drv` closures, and
//! store materialization.

mod split;

use super::*;

const PARSE_ERROR_SOURCE: &str = "let x = ; in x";

#[test]
fn native_instantiation_expr_returns_drv_path() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-instantiation-expr")?;

    let path = native.instantiate_expr(
        r#"derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
    )?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-base.drv"));
    let bytes = assert_materialized_drv(&path)?;
    assert!(bytes.starts_with(b"Derive("));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_uses_configured_parse_cache() -> Result<()> {
    let root = unique_temp_dir("native-instantiation-parse-cache");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let cache_root = root.join("parse");
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_parse_cache_root(&cache_root);
    let native = NixNative::with_options(0, options)?;
    let expr = r#"derivationStrict {
         name = "base";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
       }"#;

    let path = native.instantiate_expr(expr)?;

    assert!(path.starts_with(&store), "{}", path.display());
    let cache = ParseCache::new(&cache_root);
    let entry = cache.entry_for_source(derivation_path_wrapper_source(expr).as_bytes());
    assert!(
        entry.is_complete(),
        "native instantiation should populate the parse-cache entry"
    );

    let cached_path = native.instantiate_expr(expr)?;
    assert_eq!(cached_path, path);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_refreshes_parse_cache_analysis_facts() -> Result<()> {
    let root = unique_temp_dir("native-instantiation-parse-cache-analysis");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let cache_root = root.join("parse");
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_parse_cache_root(&cache_root);
    let native = NixNative::with_options(0, options)?;
    let expr = r#"(x: derivationStrict {
         name = "base-${builtins.toString x}";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
       }) (1 + 2)"#;
    let source = derivation_path_wrapper_source(expr);

    let (closure, _stats) = instantiate_expr_closure_with_stats(&native, expr)?;

    assert!(
        closure.root().starts_with(&store),
        "{}",
        closure.root().display()
    );
    assert_parse_cache_has_non_conservative_facts(&cache_root, source.as_bytes())?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_materializes_persistent_parse_cache() -> Result<()> {
    use crate::cache::{PersistCache, PersistParseArtifactKey};

    let root = unique_temp_dir("native-instantiation-persist-parse-cache");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let cache_root = root.join("parse");
    let persist_root = root.join("persist");
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_parse_cache_root(&cache_root);
    options.set_persist_cache_root(&persist_root);
    let native = NixNative::with_options(0, options)?;
    let expr = r#"derivationStrict {
         name = "base";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
       }"#;
    let source = derivation_path_wrapper_source(expr);

    let path = native.instantiate_expr(expr)?;

    assert!(path.starts_with(&store), "{}", path.display());
    let cache = ParseCache::new(&cache_root);
    let parse_key = cache.key_for_source(source.as_bytes());
    assert!(cache.entry_for_key(parse_key).is_complete());
    let persist = PersistCache::open(&persist_root)?;
    assert!(
        persist
            .lookup_parse_artifact(PersistParseArtifactKey::from_parse_cache_key(parse_key))?
            .is_some(),
        "raw instantiation should write a parse-keyed persistent artifact"
    );
    assert_eq!(
        fs::metadata(persist.layout().file_artifact_index_path())?.len(),
        0,
        "raw instantiation should not synthesize a persistent file-artifact key"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_cache_off_on_and_persistent_hit_preserve_drv_closure() -> Result<()> {
    use crate::cache::{PersistCache, PersistParseArtifactKey};

    let root = unique_temp_dir("native-instantiation-cache-parity");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let first_parse_root = root.join("first-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let expr = r#"let
         base = derivationStrict {
           name = "cache-parity-base";
           system = "x86_64-linux";
           builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         };
       in derivationStrict {
         name = "cache-parity-consumer";
         system = "x86_64-linux";
         builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
         input = "${base.out}";
       }"#;
    let source = derivation_path_wrapper_source(expr);

    let uncached_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    let (uncached, uncached_stats) =
        instantiate_expr_closure_with_stats(&NixNative::with_options(0, uncached_options)?, expr)?;
    assert_no_incremental_cache_activity(&uncached_stats, "cache-off native raw closure");
    assert_eq!(uncached.drvs().len(), 2);
    assert!(
        uncached.root().starts_with(&store),
        "{}",
        uncached.root().display()
    );

    let mut miss_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    miss_options.set_eval_cache_enabled(true);
    let miss = NixNative::with_options(0, miss_options)?.instantiate_expr_closure(expr)?;
    assert_eq!(miss, uncached);

    let first_parse_cache = ParseCache::new(&first_parse_root);
    let parse_key = first_parse_cache.key_for_source(source.as_bytes());
    let canaries = durable_hash_surface_canaries(
        "raw wrapper parse-cache BLAKE3",
        parse_key.as_durable_hash(),
    );
    assert!(first_parse_cache.entry_for_key(parse_key).is_complete());
    assert!(
        PersistCache::open(&persist_root)?
            .lookup_parse_artifact(PersistParseArtifactKey::from_parse_cache_key(parse_key))?
            .is_some(),
        "cache-on miss should write a durable raw parse artifact"
    );

    let observed_hits = Arc::new(Mutex::new(Vec::new()));
    let observed_hits_for_hook = Arc::clone(&observed_hits);
    let mut hit_options = TreeWalkOptions::with_store_dir(store_bytes)?;
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    hit_options.set_eval_cache_enabled(true);
    let mut hit_native = NixNative::with_options(0, hit_options)?;
    hit_native.set_persistent_parse_hit_hook(move |hit| {
        observed_hits_for_hook
            .lock()
            .expect("persistent parse hit observations lock")
            .push(hit);
    });

    let hit = hit_native.instantiate_expr_closure(expr)?;

    assert_eq!(hit, uncached);
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached native raw closure",
        &uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cache-on native raw miss closure",
        &miss,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit native raw closure",
        &hit,
        &canaries,
    );
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_key(parse_key)
            .is_complete(),
        "persistent raw parse hit should hydrate the fresh parse-cache entry"
    );
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

fn instantiate_expr_closure_with_stats(
    native: &NixNative,
    expr: &str,
) -> Result<(NativeDrvClosure, crate::eval::EvalStats)> {
    let source = derivation_path_wrapper_source(expr);
    let ir = native.lower_native_source(&source, None, None)?;
    let outcome = native.eval_instantiation_ir(&ir)?;
    let stats = *outcome.stats();
    let closure = native.native_drv_closure_from_outcome(outcome)?;
    Ok((closure, stats))
}

#[test]
fn native_instantiation_expr_force_cache_sidecar_hashes_do_not_leak_into_drv_closure() -> Result<()>
{
    let root = unique_temp_dir("native-instantiation-force-cache-leak");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let expr = r#"let
         b = builtins;
       in derivationStrict {
         name = "native-force-cache-leak";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         args = [ b.currentSystem ];
       }"#;

    let mut uncached_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    uncached_options.set_store_dir(store_bytes.clone())?;
    let (uncached, uncached_stats) =
        instantiate_expr_closure_with_stats(&NixNative::with_options(0, uncached_options)?, expr)?;
    assert_no_incremental_cache_activity(
        &uncached_stats,
        "cache-off native force-cache sidecar leak closure",
    );
    assert_eq!(uncached.drvs().len(), 1);
    assert!(
        uncached.root().starts_with(&store),
        "{}",
        uncached.root().display()
    );

    let mut first_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    first_options.set_store_dir(store_bytes.clone())?;
    first_options.set_persist_cache_root(&persist_root);
    first_options.set_eval_cache_enabled(true);
    let (first, first_stats) =
        instantiate_expr_closure_with_stats(&NixNative::with_options(0, first_options)?, expr)?;
    assert_eq!(first, uncached);
    assert_eq!(first_stats.force_cache_hits(), 0);
    assert!(
        first_stats.force_cache_misses() > 0,
        "first native force-cache run should miss before recording demand"
    );

    let mut materialize_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    materialize_options.set_store_dir(store_bytes.clone())?;
    materialize_options.set_persist_cache_root(&persist_root);
    materialize_options.set_eval_cache_enabled(true);
    let (materialized, materialized_stats) = instantiate_expr_closure_with_stats(
        &NixNative::with_options(0, materialize_options)?,
        expr,
    )?;
    assert_eq!(materialized, uncached);
    assert_eq!(materialized_stats.force_cache_hits(), 0);
    assert!(
        materialized_stats.force_cache_misses() > 0,
        "materializing native force-cache run should miss before writing persistent payloads"
    );

    let mut hit_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    hit_options.set_store_dir(store_bytes)?;
    hit_options.set_persist_cache_root(&persist_root);
    hit_options.set_eval_cache_enabled(true);
    let (hit, hit_stats) =
        instantiate_expr_closure_with_stats(&NixNative::with_options(0, hit_options)?, expr)?;
    assert_eq!(hit, uncached);
    assert!(
        hit_stats.force_cache_hits() > 0,
        "fresh native runtime should load the persistent force-cache payload"
    );
    assert_eq!(
        hit_stats.force_cache_misses(),
        0,
        "fresh native runtime should not recompute the materialized force-cache payload"
    );

    let mut canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    let hot_canary = context_free_nix_string_xxh3(b"x86_64-linux");
    canaries.extend(hot_xxh3_surface_canaries("hot xxh3", hot_canary));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached native force-cache closure",
        &uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "first native force-cache closure",
        &first,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "materialized native force-cache closure",
        &materialized,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit native force-cache closure",
        &hit,
        &canaries,
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_disabled_cache_bypasses_persistent_force_sidecar_effects() -> Result<()>
{
    use crate::cache::PersistCache;

    let root = unique_temp_dir("native-instantiation-force-cache-disabled-sidecars");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let expr = r#"let
         b = builtins;
       in derivationStrict {
         name = "native-force-cache-disabled-sidecars";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         args = [ b.currentSystem ];
       }"#;

    let mut uncached_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    uncached_options.set_store_dir(store_bytes.clone())?;
    let (uncached, uncached_stats) =
        instantiate_expr_closure_with_stats(&NixNative::with_options(0, uncached_options)?, expr)?;
    assert_no_incremental_cache_activity(
        &uncached_stats,
        "cache-off native force-cache sidecar bypass closure",
    );

    let mut first_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    first_options.set_store_dir(store_bytes.clone())?;
    first_options.set_persist_cache_root(&persist_root);
    first_options.set_eval_cache_enabled(true);
    let (first, first_stats) =
        instantiate_expr_closure_with_stats(&NixNative::with_options(0, first_options)?, expr)?;
    assert_eq!(first, uncached);
    assert_eq!(first_stats.force_cache_hits(), 0);
    assert!(
        first_stats.force_cache_misses() > 0,
        "first native force-cache run should miss before recording demand"
    );

    let mut materialize_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    materialize_options.set_store_dir(store_bytes.clone())?;
    materialize_options.set_persist_cache_root(&persist_root);
    materialize_options.set_eval_cache_enabled(true);
    let (materialized, materialized_stats) = instantiate_expr_closure_with_stats(
        &NixNative::with_options(0, materialize_options)?,
        expr,
    )?;
    assert_eq!(materialized, uncached);
    assert_eq!(materialized_stats.force_cache_hits(), 0);
    assert!(
        materialized_stats.force_cache_misses() > 0,
        "materializing native force-cache run should miss before writing persistent payloads"
    );

    let canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    let persist = PersistCache::open(&persist_root)?;
    let metadata_before = persist.node_metadata_index().latest_entries()?;
    let traces_before = persist.node_trace_log().latest_entries()?;
    let files_before = snapshot_regular_file_tree(&persist_root)?;

    let mut disabled_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    disabled_options.set_store_dir(store_bytes)?;
    disabled_options.set_persist_cache_root(&persist_root);
    let (disabled, disabled_stats) =
        instantiate_expr_closure_with_stats(&NixNative::with_options(0, disabled_options)?, expr)?;

    assert_eq!(disabled, uncached);
    assert_no_incremental_cache_activity(
        &disabled_stats,
        "disabled native force-cache sidecar bypass closure",
    );
    assert_eq!(
        persist.node_metadata_index().latest_entries()?,
        metadata_before,
        "disabled eval-cache must not mutate persistent node metadata"
    );
    assert_eq!(
        persist.node_trace_log().latest_entries()?,
        traces_before,
        "disabled eval-cache must not mutate persistent node traces"
    );
    assert_eq!(
        snapshot_regular_file_tree(&persist_root)?,
        files_before,
        "disabled eval-cache must not mutate persistent cache file contents"
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "disabled native force-cache closure",
        &disabled,
        &canaries,
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_reified_builtins_do_not_force_nix_path() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-reified-builtins")?;

    for source in [
        r#"let b = builtins; in b.derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
        r#"let b = builtins; in b.${"derivationStrict"} {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
        r#"with builtins; derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
    ] {
        let closure = native.instantiate_expr_closure(source)?;
        assert!(
            closure.root().starts_with(&store),
            "{}",
            closure.root().display()
        );
        assert!(closure.root().to_string_lossy().ends_with("-base.drv"));
    }

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_returns_drv_closure_bytes() -> Result<()> {
    let native = NixNative::new(0)?;

    let closure = native.instantiate_expr_closure(
        r#"derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
    )?;

    assert_eq!(
        closure.root(),
        Path::new("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv")
    );
    let root_bytes = closure
        .drvs()
        .get(closure.root())
        .expect("root derivation bytes are recorded");
    assert!(root_bytes.starts_with(b"Derive("));
    assert!(nix_compat::derivation::Derivation::from_aterm_bytes(root_bytes).is_ok());
    Ok(())
}

#[test]
fn native_instantiation_expr_orders_quoted_non_ascii_derivation_env_attrs() -> Result<()> {
    let native = NixNative::new(0)?;

    let closure = native.instantiate_expr_closure(
        r#"derivationStrict {
             name = "quoted-order";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             zz = "after-system";
             "é" = "non-ascii";
             aardvark = "before-builder";
           }"#,
    )?;

    let root_bytes = closure
        .drvs()
        .get(closure.root())
        .expect("root derivation bytes are recorded");
    assert!(nix_compat::derivation::Derivation::from_aterm_bytes(root_bytes).is_ok());
    let root_text = std::str::from_utf8(root_bytes)?;
    assert_substrings_in_order(
        root_text,
        &[
            r#"("aardvark","before-builder")"#,
            r#"("builder","/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder")"#,
            r#"("name","quoted-order")"#,
            r#"("out","/nix/store/"#,
            r#"("system","x86_64-linux")"#,
            r#"("zz","after-system")"#,
            r#"("é","non-ascii")"#,
        ],
    );
    Ok(())
}

#[test]
fn native_instantiation_expr_closure_includes_input_derivation_bytes() -> Result<()> {
    let native = NixNative::new(0)?;

    let closure = native.instantiate_expr_closure(
        r#"let
             base = derivationStrict {
               name = "base";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
           in derivationStrict {
             name = "consumer";
             system = "x86_64-linux";
             builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
             input = "${base.out}";
           }"#,
    )?;

    let base = Path::new("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv");
    assert!(closure.drvs().contains_key(base));
    assert_eq!(closure.drvs().len(), 2);
    let root_bytes = closure
        .drvs()
        .get(closure.root())
        .expect("root derivation bytes are recorded");
    let root_text = std::str::from_utf8(root_bytes)?;
    assert!(root_text.contains("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv"));
    Ok(())
}

#[test]
fn native_instantiation_expr_materializes_input_drv_closure() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-materialized-closure")?;
    let expr = r#"let
         base = derivationStrict {
           name = "base";
           system = "x86_64-linux";
           builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         };
       in derivationStrict {
         name = "consumer";
         system = "x86_64-linux";
         builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
         input = "${base.out}";
       }"#;

    let expected = native.instantiate_expr_closure(expr)?;
    assert_eq!(expected.drvs().len(), 2);
    assert!(expected.drvs().keys().all(|path| !path.exists()));

    let path = native.instantiate_expr(expr)?;

    assert_eq!(path, expected.root());
    assert!(path.starts_with(&store), "{}", path.display());
    for (path, expected_bytes) in expected.drvs() {
        let actual = assert_materialized_drv(path)?;
        assert_eq!(&actual, expected_bytes, "{}", path.display());
    }

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_refuses_conflicting_existing_drv() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("native-conflicting-drv")?;
    let expr = r#"derivationStrict {
         name = "base";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
       }"#;
    let closure = native.instantiate_expr_closure(expr)?;
    let parent = closure
        .root()
        .parent()
        .ok_or_else(|| anyhow::anyhow!("root derivation path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::write(closure.root(), b"not a derivation")?;

    let error = native
        .instantiate_expr(expr)
        .expect_err("conflicting derivation file must not be overwritten");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Internal { message })
                if message.contains("refusing to overwrite existing derivation")
        ),
        "{error:?}"
    );
    assert_eq!(fs::read(closure.root())?, b"not a derivation");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_closure_supports_floating_ca_bytes() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-floating-ca")?;
    let expr = r#"derivationStrict {
         name = "ca";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         __contentAddressed = true;
         outputHashAlgo = "sha256";
         outputHashMode = "recursive";
       }"#;

    let path = native.instantiate_expr(expr)?;
    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-ca.drv"));
    let materialized = assert_materialized_drv(&path)?;

    let closure = native.instantiate_expr_closure(expr)?;
    assert_eq!(closure.root(), path);
    let bytes = closure
        .drvs()
        .get(closure.root())
        .expect("floating CA root derivation bytes are recorded");
    let text = std::str::from_utf8(bytes)?;
    assert!(text.contains(r#""r:sha256""#));
    assert!(text.contains(r#"("out","","r:sha256","")"#));
    assert_eq!(&materialized, bytes);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_path_instantiation_materializes_downstream_deferred_drv_bytes() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-deferred-drv")?;
    let expr = r#"let
         base = derivationStrict {
           name = "ca";
           system = "x86_64-linux";
           builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           __contentAddressed = true;
           outputHashAlgo = "sha256";
           outputHashMode = "recursive";
         };
       in derivationStrict {
         name = "consumer";
         system = "x86_64-linux";
         builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
         input = "${base.out}";
       }"#;

    let path = native.instantiate_expr(expr)?;
    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-consumer.drv"));

    let closure = native.instantiate_expr_closure(expr)?;
    assert_eq!(closure.root(), path);
    assert_eq!(closure.drvs().len(), 2);
    for (path, expected_bytes) in closure.drvs() {
        let actual = assert_materialized_drv(path)?;
        assert_eq!(&actual, expected_bytes, "{}", path.display());
    }

    let root_bytes = closure
        .drvs()
        .get(closure.root())
        .expect("deferred consumer root derivation bytes are recorded");
    let root_text = std::str::from_utf8(root_bytes)?;
    assert!(root_text.contains(r#"("out","/"#));
    assert!(!root_text.contains(r#"("out","","","")"#));
    assert!(!root_text.contains(r#"("out","")"#));
    assert_eq!(root_text.matches(r#"("out","/"#).count(), 2);
    let ca_drv = closure
        .drvs()
        .keys()
        .find(|path| path.to_string_lossy().ends_with("-ca.drv"))
        .expect("CA input derivation is recorded");
    assert!(root_text.contains(&ca_drv.display().to_string()));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn configured_cpp_nix_native_drv_closure_bytes_match_cli() -> Result<()> {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping native drv byte oracle check");
        return Ok(());
    };
    let native = NixNative::new(0)?;
    let nonce = unique_store_name("native-drv-oracle");
    let base_name = format!("base-{nonce}");
    let consumer_name = format!("consumer-{nonce}");
    let ca_name = format!("ca-{nonce}");
    let ca_consumer_name = format!("ca-consumer-{nonce}");
    let quoted_order_name = format!("quoted-order-{nonce}");

    for expr in [
        format!(
            r#"derivationStrict {{
             name = "{base_name}";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }}"#
        ),
        format!(
            r#"let
             base = derivationStrict {{
               name = "{base_name}";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             }};
           in derivationStrict {{
             name = "{consumer_name}";
             system = "x86_64-linux";
             builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
             input = "${{base.out}}";
           }}"#
        ),
        format!(
            r#"derivationStrict {{
             name = "{ca_name}";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             __contentAddressed = true;
             outputHashAlgo = "sha256";
             outputHashMode = "recursive";
           }}"#
        ),
        format!(
            r#"let
             base = derivationStrict {{
               name = "{ca_name}";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             }};
           in derivationStrict {{
             name = "{ca_consumer_name}";
             system = "x86_64-linux";
             builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
             input = "${{base.out}}";
           }}"#
        ),
        format!(
            r#"derivationStrict {{
             name = "{quoted_order_name}";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             zz = "after-system";
             "é" = "non-ascii";
             aardvark = "before-builder";
           }}"#
        ),
    ] {
        let closure = native.instantiate_expr_closure(&expr)?;
        let instantiate_output = Command::new(&oracle).args(["--expr", &expr]).output()?;
        if !instantiate_output.status.success()
            && String::from_utf8_lossy(&instantiate_output.stderr)
                .contains("experimental Nix feature")
        {
            eprintln!("configured C++ Nix oracle skipped experimental expression {expr:?}");
            continue;
        }
        assert!(
            instantiate_output.status.success(),
            "C++ Nix oracle unexpectedly rejected {expr:?}: {}",
            String::from_utf8_lossy(&instantiate_output.stderr)
        );

        for path in closure.drvs().keys() {
            assert!(
                path.exists(),
                "C++ Nix oracle did not materialize {} for {expr:?}",
                path.display()
            );
        }

        let source = derivation_path_wrapper_source(&expr);
        let output = Command::new(&oracle)
            .args(["--eval", "--strict", "--expr", &source])
            .output()?;
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("experimental Nix feature")
        {
            eprintln!("configured C++ Nix oracle skipped experimental expression {expr:?}");
            continue;
        }
        assert!(
            output.status.success(),
            "C++ Nix oracle unexpectedly rejected {expr:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let root: String = serde_json::from_slice(&output.stdout)?;
        assert_eq!(closure.root(), Path::new(&root), "{expr}");

        for (path, bytes) in closure.drvs() {
            let expected = fs::read(path)?;
            assert_eq!(bytes, &expected, "{}", path.display());
        }
    }

    Ok(())
}

fn assert_substrings_in_order(haystack: &str, needles: &[&str]) {
    let mut cursor = 0;
    for needle in needles {
        let Some(relative_offset) = haystack[cursor..].find(needle) else {
            panic!("expected to find {needle:?} after byte offset {cursor} in {haystack}");
        };
        cursor += relative_offset + needle.len();
    }
}

#[test]
fn native_instantiation_rejects_non_derivations() -> Result<()> {
    let native = NixNative::new(0)?;

    let error = native
        .instantiate_expr("1")
        .expect_err("non-derivations should not instantiate");

    assert!(matches!(
        error.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::EvalError { .. })
    ));
    Ok(())
}

#[test]
fn native_instantiation_reports_tree_walk_errors_with_source() -> Result<()> {
    let native = NixNative::new(0)?;

    let materialized_error = native
        .instantiate_expr("1 + true")
        .expect_err("tree-walk semantic errors should not instantiate");
    assert_tree_walk_source_report(&materialized_error);

    let closure_error = native
        .instantiate_expr_closure("1 + true")
        .expect_err("tree-walk semantic errors should not produce closures");
    assert_tree_walk_source_report(&closure_error);
    Ok(())
}

fn assert_tree_walk_source_report(error: &anyhow::Error) {
    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("type error should surface as a native eval error: {error:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(message.contains("expr.nix"), "{message}");
    assert!(message.contains("1 + true"), "{message}");
    assert!(!message.contains(".drvPath"), "{message}");
}

#[test]
fn native_instantiation_reports_parse_errors_with_source() -> Result<()> {
    let native = NixNative::new(0)?;

    let error = native
        .instantiate_expr(PARSE_ERROR_SOURCE)
        .expect_err("parse errors should stay fallback-eligible");

    let Some(NativeEvalError::Unsupported {
        feature,
        span: Some(_),
    }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("parse errors should surface as unsupported fallback errors: {error:?}");
    };
    assert!(
        feature.contains("native expression parse failure"),
        "{feature}"
    );
    assert!(feature.contains("aos_nix::parse::"), "{feature}");
    assert!(feature.contains("expr.nix"), "{feature}");
    assert!(feature.contains(PARSE_ERROR_SOURCE), "{feature}");
    assert!(!feature.contains(".drvPath"), "{feature}");
    Ok(())
}

