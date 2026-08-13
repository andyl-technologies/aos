//! Tests for file-backed `-A` attribute-path instantiation and selector parsing.

mod split;

use super::*;

mod selector_syntax;

#[test]
fn native_instantiation_imports_file_attr_path() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs.hello = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let path = native.instantiate(&file, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-base.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_materializes_persistent_root_parse_cache() -> Result<()> {
    use crate::cache::{ParseCache, ParseFileKey, PersistCache, PersistFileArtifactKey};

    let root = unique_temp_dir("aos-nix-native-instantiate-persist-root");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let parse_root = root.join("parse");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs.hello = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;
    let source = fs::read(&file)?;
    let realpath = fs::canonicalize(&file)?;
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_parse_cache_root(&parse_root);
    options.set_persist_cache_root(&persist_root);
    let native = NixNative::with_options(0, options)?;

    let path = native.instantiate(&file, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    let parse_cache = ParseCache::new(&parse_root);
    assert!(parse_cache.entry_for_source(&source).is_complete());
    let file_key = ParseFileKey::for_source(&realpath, &source);
    let artifact_key =
        PersistFileArtifactKey::from_parse_file_key(&file_key, parse_cache.key_for_source(&source));
    assert!(
        PersistCache::open(&persist_root)?
            .lookup_file_artifact(artifact_key)?
            .is_some(),
        "file-backed native root parse artifact should be written durably"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_root_persists_refreshed_analysis_facts() -> Result<()> {
    use crate::cache::{ParseCache, ParseFileKey, PersistCache, PersistFileArtifactKey};

    let root = unique_temp_dir("aos-nix-native-file-parse-analysis");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let first_parse_root = root.join("first-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let file = root.join("default.nix");
    let source = b"(x: x + 1) (1 + 2)";
    fs::write(&file, source)?;
    let realpath = fs::canonicalize(&file)?;
    let source_hint = realpath.to_string_lossy().into_owned();

    let mut first_options = TreeWalkOptions::new();
    first_options.set_parse_cache_root(&first_parse_root);
    first_options.set_persist_cache_root(&persist_root);
    let first_native = NixNative::with_options(0, first_options)?;
    let first_ir = first_native.lower_native_source_bytes(
        source,
        Some(source_hint.clone()),
        Some(realpath.as_path()),
        None,
        None,
    )?;
    assert_ir_has_non_conservative_facts(&first_ir);
    assert_parse_cache_has_non_conservative_facts(&first_parse_root, source)?;
    let first_cache = ParseCache::new(&first_parse_root);
    let parse_key = first_cache.key_for_source(source);
    let file_key = ParseFileKey::for_source(&realpath, source);
    assert!(
        PersistCache::open(&persist_root)?
            .lookup_file_artifact(PersistFileArtifactKey::from_parse_file_key(
                &file_key, parse_key
            ))?
            .is_some(),
        "native file root should persist the refreshed parse artifact"
    );
    let probe_parse_root = root.join("probe-parse");
    let persisted = PersistCache::open(&persist_root)?
        .load_parse_cache_source_from_index(&ParseCache::new(&probe_parse_root), &realpath, source)?
        .expect("persisted file-root artifact hydrates");
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

    let second_ir = second_native.lower_native_source_bytes(
        source,
        Some(source_hint),
        Some(realpath.as_path()),
        None,
        None,
    )?;

    assert_ir_has_non_conservative_facts(&second_ir);
    assert_parse_cache_has_non_conservative_facts(&second_parse_root, source)?;
    assert_eq!(
        observed_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .clone(),
        vec![NativePersistentParseHit::Source]
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_cache_off_on_and_persistent_hit_preserve_drv_closure() -> Result<()> {
    use crate::cache::{ParseCache, ParseFileKey, PersistCache, PersistFileArtifactKey};

    let root = unique_temp_dir("aos-nix-native-instantiate-file-cache-parity");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let first_parse_root = root.join("first-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          base = derivationStrict {
            name = "file-cache-parity-base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        in {
          pkgs.hello = derivationStrict {
            name = "file-cache-parity-consumer";
            system = "x86_64-linux";
            builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
            input = "${base.out}";
          };
        }"#,
    )?;
    let source = fs::read(&file)?;
    let realpath = fs::canonicalize(&file)?;
    let store_bytes = store.as_os_str().as_bytes().to_vec();

    let uncached_options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
    let (uncached, uncached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, uncached_options)?,
        &file,
        "pkgs.hello",
    )?;
    assert_no_incremental_cache_activity(&uncached_stats, "cache-off native file closure");
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
    let miss =
        NixNative::with_options(0, miss_options)?.instantiate_closure(&file, "pkgs.hello")?;
    assert_eq!(miss, uncached);

    let first_parse_cache = ParseCache::new(&first_parse_root);
    let parse_key = first_parse_cache.key_for_source(&source);
    let file_key = ParseFileKey::for_source(&realpath, &source);
    let mut canaries =
        durable_hash_surface_canaries("file root parse-cache BLAKE3", parse_key.as_durable_hash());
    canaries.extend(durable_hash_surface_canaries(
        "file root content BLAKE3",
        file_key.content_hash().as_durable_hash(),
    ));
    assert!(first_parse_cache.entry_for_key(parse_key).is_complete());
    assert!(
        PersistCache::open(&persist_root)?
            .lookup_file_artifact(PersistFileArtifactKey::from_parse_file_key(
                &file_key, parse_key
            ))?
            .is_some(),
        "cache-on miss should write a durable file-backed parse artifact"
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

    let hit = hit_native.instantiate_closure(&file, "pkgs.hello")?;

    assert_eq!(hit, uncached);
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached native file closure",
        &uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cache-on native file miss closure",
        &miss,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit native file closure",
        &hit,
        &canaries,
    );
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_key(parse_key)
            .is_complete(),
        "persistent file-backed parse hit should hydrate the fresh parse-cache entry"
    );
    assert_eq!(
        observed_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .clone(),
        vec![NativePersistentParseHit::Source]
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_force_cache_sidecar_hashes_do_not_leak_into_drv_closure() -> Result<()>
{
    let root = unique_temp_dir("native-file-instantiation-force-cache-leak");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
        in {
          pkgs.hello = derivationStrict {
            name = "native-file-force-cache-leak";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [ b.currentSystem ];
          };
        }"#,
    )?;
    let store_bytes = store.as_os_str().as_bytes().to_vec();

    let mut uncached_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    uncached_options.set_store_dir(store_bytes.clone())?;
    let (uncached, uncached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, uncached_options)?,
        &file,
        "pkgs.hello",
    )?;
    assert_no_incremental_cache_activity(
        &uncached_stats,
        "cache-off native file force-cache sidecar leak closure",
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
    let (first, first_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, first_options)?,
        &file,
        "pkgs.hello",
    )?;
    assert_eq!(first, uncached);
    assert_eq!(first_stats.force_cache_hits(), 0);
    assert!(
        first_stats.force_cache_misses() > 0,
        "first native file force-cache run should miss before recording demand"
    );

    let mut materialize_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    materialize_options.set_store_dir(store_bytes.clone())?;
    materialize_options.set_persist_cache_root(&persist_root);
    materialize_options.set_eval_cache_enabled(true);
    let (materialized, materialized_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, materialize_options)?,
        &file,
        "pkgs.hello",
    )?;
    assert_eq!(materialized, uncached);
    assert_eq!(materialized_stats.force_cache_hits(), 0);
    assert!(
        materialized_stats.force_cache_misses() > 0,
        "materializing native file force-cache run should miss before writing persistent payloads"
    );

    let mut hit_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    hit_options.set_store_dir(store_bytes)?;
    hit_options.set_persist_cache_root(&persist_root);
    hit_options.set_eval_cache_enabled(true);
    let (hit, hit_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, hit_options)?,
        &file,
        "pkgs.hello",
    )?;
    assert_eq!(hit, uncached);
    assert!(
        hit_stats.force_cache_hits() > 0,
        "fresh native file runtime should load the persistent force-cache payload"
    );
    assert_eq!(
        hit_stats.force_cache_misses(),
        0,
        "fresh native file runtime should not recompute the materialized force-cache payload"
    );

    let mut canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    let hot_canary = context_free_nix_string_xxh3(b"x86_64-linux");
    canaries.extend(hot_xxh3_surface_canaries("hot xxh3", hot_canary));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached native file force-cache closure",
        &uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "first native file force-cache closure",
        &first,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "materialized native file force-cache closure",
        &materialized,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit native file force-cache closure",
        &hit,
        &canaries,
    );

    Ok(())
}

#[test]
fn native_file_instantiation_disabled_cache_bypasses_persistent_force_sidecar_effects() -> Result<()>
{
    let root = unique_temp_dir("native-file-instantiation-force-cache-disabled-sidecars");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
        in {
          pkgs.hello = derivationStrict {
            name = "native-file-force-cache-disabled-sidecars";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [ b.currentSystem ];
          };
        }"#,
    )?;
    let store_bytes = store.as_os_str().as_bytes().to_vec();

    let mut uncached_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    uncached_options.set_store_dir(store_bytes.clone())?;
    let (uncached, uncached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, uncached_options)?,
        &file,
        "pkgs.hello",
    )?;
    assert_no_incremental_cache_activity(
        &uncached_stats,
        "cache-off native file force-cache sidecar bypass closure",
    );

    let mut first_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    first_options.set_store_dir(store_bytes.clone())?;
    first_options.set_persist_cache_root(&persist_root);
    first_options.set_eval_cache_enabled(true);
    let (first, first_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, first_options)?,
        &file,
        "pkgs.hello",
    )?;
    assert_eq!(first, uncached);
    assert_eq!(first_stats.force_cache_hits(), 0);
    assert!(
        first_stats.force_cache_misses() > 0,
        "first native file force-cache run should miss before recording demand"
    );

    let mut materialize_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    materialize_options.set_store_dir(store_bytes.clone())?;
    materialize_options.set_persist_cache_root(&persist_root);
    materialize_options.set_eval_cache_enabled(true);
    let (materialized, materialized_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, materialize_options)?,
        &file,
        "pkgs.hello",
    )?;
    assert_eq!(materialized, uncached);
    assert_eq!(materialized_stats.force_cache_hits(), 0);
    assert!(
        materialized_stats.force_cache_misses() > 0,
        "materializing native file force-cache run should miss before writing persistent payloads"
    );

    let canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    let persist = PersistCache::open(&persist_root)?;
    let metadata_before = persist.node_metadata_index().latest_entries()?;
    let traces_before = persist.node_trace_log().latest_entries()?;
    let force_sidecar_paths = persistent_force_sidecar_paths(&persist);
    let force_sidecar_files_before =
        snapshot_regular_file_paths(&persist_root, &force_sidecar_paths)?;

    let mut disabled_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?;
    disabled_options.set_store_dir(store_bytes)?;
    disabled_options.set_persist_cache_root(&persist_root);
    let (disabled, disabled_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, disabled_options)?,
        &file,
        "pkgs.hello",
    )?;

    assert_eq!(disabled, uncached);
    assert_no_incremental_cache_activity(
        &disabled_stats,
        "disabled native file force-cache sidecar bypass closure",
    );
    assert_eq!(
        persist.node_metadata_index().latest_entries()?,
        metadata_before,
        "disabled eval-cache must not mutate persistent file node metadata"
    );
    assert_eq!(
        persist.node_trace_log().latest_entries()?,
        traces_before,
        "disabled eval-cache must not mutate persistent file node traces"
    );
    assert_eq!(
        snapshot_regular_file_paths(&persist_root, &force_sidecar_paths)?,
        force_sidecar_files_before,
        "disabled eval-cache must not mutate persistent file force-cache sidecar contents"
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "disabled native file force-cache closure",
        &disabled,
        &canaries,
    );

    Ok(())
}

#[test]
fn native_file_instantiation_hydrates_persistent_root_parse_cache() -> Result<()> {
    use crate::cache::{MaterializationDecision, ParseCache, ParseFileKey, PersistCache};

    let root = unique_temp_dir("aos-nix-native-instantiate-persist-root-hit");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let seed_parse_root = root.join("seed-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs.hello = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;
    let source = fs::read(&file)?;
    let realpath = fs::canonicalize(&file)?;
    let marker = "persist-seed-marker.nix";
    let seed_parse = ParseCache::new(&seed_parse_root);
    let parsed = seed_parse.load_or_parse_bytes(&source, Some(marker.to_owned()))?;
    let file_key = ParseFileKey::for_source(&realpath, &source);
    PersistCache::open(&persist_root)?.materialize_parse_artifact_entry_indexed(
        &file_key,
        parsed.key,
        &parsed.entry,
        MaterializationDecision::Materialize,
    )?;

    let mut second_options =
        TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    second_options.set_parse_cache_root(&second_parse_root);
    second_options.set_persist_cache_root(&persist_root);
    let second = NixNative::with_options(0, second_options)?;
    let second_path = second.instantiate(&file, "pkgs.hello")?;

    assert!(second_path.starts_with(&store), "{}", second_path.display());
    let hydrated_entry = ParseCache::new(&second_parse_root).entry_for_source(&source);
    assert!(
        hydrated_entry.is_complete(),
        "persistent native root hit should hydrate the fresh parse-cache entry"
    );
    let meta = hydrated_entry.read_artifact_bundle()?.decode_meta()?;
    assert_eq!(meta.source_hint.as_deref(), Some(marker));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_imports_directory_default_file() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-dir")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join("default.nix"),
        r#"{
          pkgs.hello = derivationStrict {
            name = "dir-default";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let path = native.instantiate(&dir, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-dir-default.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_restricted_mode_rejects_unallowed_root_file_before_parse() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-instantiate-restricted-denied");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let file = root.join("default.nix");
    fs::write(&file, b"let { body = 1; }")?;
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_eval_mode(EvalMode::Restricted);
    let native = NixNative::with_options(0, options)?;

    let error = native
        .instantiate(&file, "")
        .expect_err("restricted mode should reject unallowed root files before parsing");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("restricted path policy should surface as a native eval error: {error:?}");
    };
    assert!(
        message.contains("Restricted evaluation forbids filesystem access"),
        "{message}"
    );
    assert!(
        message.contains(&file.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(
        !message.contains("native expression parse failure"),
        "{message}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_restricted_mode_accepts_allowed_directory_root_file() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-instantiate-restricted-allowed");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join("default.nix"),
        r#"{
          pkgs.hello = derivationStrict {
            name = "restricted-allowed";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_eval_mode(EvalMode::Restricted);
    options.add_allowed_path(root.as_os_str().as_bytes().to_vec())?;
    let native = NixNative::with_options(0, options)?;

    let path = native.instantiate(&dir, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-restricted-allowed.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_empty_attr_path_selects_root() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-empty-attr")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"derivationStrict {
          name = "root";
          system = "x86_64-linux";
          builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        }"#,
    )?;

    let path = native.instantiate(&file, "")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-root.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_accepts_quoted_attr_path_segments() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-quoted")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          "pkgs.with.dot".hello = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."hello\${name}" = derivationStrict {
            name = "literal-interpolation";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."hello\\\${name}" = derivationStrict {
            name = "escaped-interpolation";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."concat.with.dot" = derivationStrict {
            name = "concat";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."weird/key+ name;let" = derivationStrict {
            name = "weird";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let path = native.instantiate(&file, r#""pkgs.with.dot".hello"#)?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-base.drv"));
    let _ = assert_materialized_drv(&path)?;

    let literal_interpolation = native.instantiate(&file, r#"pkgs."hello${name}""#)?;
    assert!(
        literal_interpolation
            .to_string_lossy()
            .ends_with("-literal-interpolation.drv")
    );
    let _ = assert_materialized_drv(&literal_interpolation)?;

    let escaped_interpolation = native.instantiate(&file, r#"pkgs."hello\${name}""#)?;
    assert!(
        escaped_interpolation
            .to_string_lossy()
            .ends_with("-escaped-interpolation.drv")
    );
    let _ = assert_materialized_drv(&escaped_interpolation)?;

    let concatenated = native.instantiate(&file, r#"pkgs.concat"."with"."dot"#)?;
    assert!(concatenated.to_string_lossy().ends_with("-concat.drv"));
    let _ = assert_materialized_drv(&concatenated)?;

    let weird = native.instantiate(&file, "pkgs.weird/key+ name;let")?;
    assert!(weird.to_string_lossy().ends_with("-weird.drv"));
    let _ = assert_materialized_drv(&weird)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_auto_calls_function_files_with_default_arguments() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-function")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{ system ? "x86_64-linux" }: {
          pkgs.hello = derivationStrict {
            name = "base";
            inherit system;
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let path = native.instantiate(&file, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-base.drv"));
    let materialized = assert_materialized_drv(&path)?;

    let closure = native.instantiate_closure(&file, "pkgs.hello")?;
    assert_eq!(closure.root(), path);
    assert_eq!(closure.drvs().len(), 1);
    assert_eq!(
        closure
            .drvs()
            .get(closure.root())
            .expect("function-file root derivation bytes are recorded"),
        &materialized,
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_auto_calls_formal_set_functions_along_attr_path() -> Result<()> {
    let (native, root, store) =
        native_with_temp_store("aos-nix-native-instantiate-nested-function")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs = { variant ? "nested" }: {
            hello = { suffix ? variant }: derivationStrict {
              name = suffix;
              system = "x86_64-linux";
              builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            };
          };
        }"#,
    )?;

    let path = native.instantiate(&file, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-nested.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_selection_path_indexes_lists() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-list-index")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs = [
            {
              hello = derivationStrict {
                name = "first";
                system = "x86_64-linux";
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
            }
            {
              hello = derivationStrict {
                name = "second";
                system = "x86_64-linux";
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
            }
          ];
        }"#,
    )?;

    let first = native.instantiate(&file, "pkgs.0.hello")?;
    assert!(first.starts_with(&store), "{}", first.display());
    assert!(first.to_string_lossy().ends_with("-first.drv"));
    let _ = assert_materialized_drv(&first)?;

    let second = native.instantiate(&file, r#"pkgs."01".hello"#)?;
    assert!(second.starts_with(&store), "{}", second.display());
    assert!(second.to_string_lossy().ends_with("-second.drv"));
    let _ = assert_materialized_drv(&second)?;

    let error = native
        .instantiate(&file, "pkgs.2.hello")
        .expect_err("out-of-range selection-path list indexes should fail");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message })
                if message.contains("list index 2 out of bounds")
        ),
        "unexpected error: {error:?}"
    );

    let error = native
        .instantiate(&file, "pkgs.4294967295.hello")
        .expect_err("u32::MAX selection-path list indexes should still be indexes");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message })
                if message.contains("list index 4294967295 out of bounds")
        ),
        "unexpected error: {error:?}"
    );

    let error = native
        .instantiate(&file, "pkgs.4294967296.hello")
        .expect_err("u32::MAX + 1 selection-path segments should be attribute names");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message }) if message.contains("expected attrs")
        ),
        "unexpected error: {error:?}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}
