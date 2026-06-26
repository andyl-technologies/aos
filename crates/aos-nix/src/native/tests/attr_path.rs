//! Tests for file-backed `-A` attribute-path instantiation and selector parsing.

use super::*;

const PARSE_ERROR_SOURCE: &str = "let x = ; in x";

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
fn native_file_instantiation_cache_off_on_and_persistent_hit_preserve_drv_closure() -> Result<()> {
    use crate::cache::{
        DurableBlake3Hash, ParseCache, ParseFileKey, PersistCache, PersistFileArtifactKey,
    };

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
    let uncached =
        NixNative::with_options(0, uncached_options)?.instantiate_closure(&file, "pkgs.hello")?;
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
    let mut canaries = durable_hash_surface_canaries(
        "file root parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(parse_key.as_bytes()),
    );
    canaries.extend(durable_hash_surface_canaries(
        "file root content BLAKE3",
        file_key.content_hash(),
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

fn instantiate_file_closure_with_stats(
    native: &NixNative,
    file: &Path,
    attr: &str,
) -> Result<(NativeDrvClosure, crate::eval::EvalStats)> {
    let attr_path = attr_path_drv_path_segments(attr)?;
    let mut options = native.instantiation_options();
    let file = native_source_file(file, &options)?;
    let source_name = path_bytes(&file)?;
    let source_name_text = String::from_utf8_lossy(&source_name);
    let source = fs::read(&file).map_err(|source| NativeEvalError::EvalError {
        message: format!(
            "failed to read native instantiation source {}: {source}",
            source_name_text
        ),
    })?;
    let diagnostic_source = std::str::from_utf8(&source)
        .ok()
        .map(|source| NativeDiagnosticSource::new(source_name_text.as_ref(), source, None));
    let base = file.parent().unwrap_or_else(|| Path::new("/"));
    options.set_path_literal_base(path_bytes(base)?)?;
    let ir = native.lower_native_source_bytes(
        &source,
        Some(source_name_text.to_string()),
        Some(file.as_path()),
        None,
        diagnostic_source,
    )?;
    if let Some((feature, span)) = native_instantiation_cli_fallback_feature(&ir, &native.options) {
        return Err(NativeEvalError::Unsupported {
            feature: feature.to_string(),
            span: Some(crate::error::SrcSpan {
                start: span.start,
                end: span.end,
            }),
        }
        .into());
    }
    let outcome = eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
        &ir,
        &attr_path,
        options,
        source_name.clone(),
        source.clone(),
        native.ifd_realizer.clone(),
        native.eval_cache.clone(),
    )
    .map_err(|error| match diagnostic_source {
        Some(diagnostic_source) => native_eval_error_with_source(error, diagnostic_source),
        None => native_eval_error(error, None),
    })?;
    let stats = *outcome.stats();
    native.observe_eval_cache(&outcome);
    let closure = native.native_drv_closure_from_outcome(outcome)?;
    Ok((closure, stats))
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
    assert_eq!(uncached_stats.force_cache_hits(), 0);
    assert_eq!(uncached_stats.force_cache_misses(), 0);
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
fn native_file_instantiation_comment_only_leaf_edit_preserves_drv_closure() -> Result<()> {
    use crate::cache::{DurableBlake3Hash, ParseCache, ParseFileKey};

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
    let cached_second = cached_second_native.instantiate_closure(&file, "pkgs.hello")?;

    assert_eq!(cached_second, uncached_first);
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
        DurableBlake3Hash::from_bytes(first_parse_key.as_bytes()),
    );
    canaries.extend(durable_hash_surface_canaries(
        "changed comment leaf parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(second_parse_key.as_bytes()),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "initial comment leaf content BLAKE3",
        first_leaf_key.content_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "changed comment leaf content BLAKE3",
        second_leaf_key.content_hash(),
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
    use crate::cache::{DurableBlake3Hash, ParseCache, ParseFileKey};

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
    let cached_second = cached_second_native.instantiate_closure(&file, "pkgs.hello")?;

    assert_eq!(cached_second, uncached_first);
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
        DurableBlake3Hash::from_bytes(first_parse_key.as_bytes()),
    );
    canaries.extend(durable_hash_surface_canaries(
        "changed unused leaf parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(second_parse_key.as_bytes()),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "initial unused leaf content BLAKE3",
        first_leaf_key.content_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "changed unused leaf content BLAKE3",
        second_leaf_key.content_hash(),
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

#[test]
fn native_file_instantiation_hydrates_persistent_root_parse_cache() -> Result<()> {
    use crate::cache::{
        MaterializationDecision, ParseCache, ParseCacheMeta, ParseFileKey, PersistCache,
    };

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
    let meta = fs::read_to_string(hydrated_entry.meta_path())?;
    let meta = ParseCacheMeta::from_toml(&meta)?;
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
fn native_file_instantiation_reports_parse_errors_with_source() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("aos-nix-native-instantiate-parse-error")?;
    let file = root.join("default.nix");
    fs::write(&file, PARSE_ERROR_SOURCE.as_bytes())?;

    let error = native
        .instantiate(&file, "")
        .expect_err("file parse errors should stay fallback-eligible");

    let Some(NativeEvalError::Unsupported { feature, .. }) =
        error.downcast_ref::<NativeEvalError>()
    else {
        panic!("parse errors should surface as unsupported fallback errors: {error:?}");
    };
    assert!(
        feature.contains("native expression parse failure"),
        "{feature}"
    );
    assert!(feature.contains("aos_nix::parse::"), "{feature}");
    assert!(
        feature.contains(&file.to_string_lossy().to_string()),
        "{feature}"
    );
    assert!(feature.contains(PARSE_ERROR_SOURCE), "{feature}");
    assert!(!feature.contains("import "), "{feature}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_imported_parse_cache_errors_with_source() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-instantiate-imported-parse-cache-error");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_parse_cache_root(root.join("parse-cache"));
    let native = NixNative::with_options(0, options)?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(&child, PARSE_ERROR_SOURCE.as_bytes())?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("imported parse errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported parse error should surface as a native eval error: {error:?}");
    };
    assert!(
        message.contains("failed to parse imported file"),
        "{message}"
    );
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains(PARSE_ERROR_SOURCE), "{message}");
    assert!(!message.contains("import ./child.nix"), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_imported_scope_errors_with_source() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-imported-scope-error")?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(&child, b"missingImportedName")?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("imported scope errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported scope error should surface as a native eval error: {error:?}");
    };
    assert!(
        message.contains("failed to resolve imported file"),
        "{message}"
    );
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains("missingImportedName"), "{message}");
    assert!(!message.contains("import ./child.nix"), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_tree_walk_errors_with_source() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("aos-nix-native-instantiate-eval-error")?;
    let file = root.join("default.nix");
    fs::write(&file, b"{ broken = 1 + true; }")?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("file tree-walk errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("type error should surface as a native eval error: {error:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(
        message.contains(&file.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains("1 + true"), "{message}");
    assert!(!message.contains("import "), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_imported_tree_walk_errors_with_source() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-imported-eval-error")?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(&child, b"1 + true")?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("imported tree-walk errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported type error should surface as a native eval error: {error:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains("1 + true"), "{message}");
    assert!(!message.contains("import ./child.nix"), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_imported_context_labels_with_source() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-imported-eval-context")?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(
        &child,
        br#"builtins.addErrorContext "child context" (1 + true)"#,
    )?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("imported tree-walk errors with child contexts should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported type error should surface as a native eval error: {error:?}");
    };
    assert!(
        message.contains("while evaluating: child context"),
        "{message}"
    );
    assert!(message.contains("type error"), "{message}");
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains("1 + true"), "{message}");
    assert!(message.contains("child context"), "{message}");
    assert!(!message.contains("import ./child.nix"), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_does_not_render_non_utf8_imported_errors_against_root() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-imported-non-utf8-eval-error")?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(&child, b"1 + true # \xff\n")?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("non-UTF8 imported tree-walk errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported type error should surface as a native eval error: {error:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(
        !message.contains(&file.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(!message.contains("import ./child.nix"), "{message}");

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

#[test]
fn native_instantiation_numeric_selection_segments_require_lists() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("aos-nix-native-instantiate-numeric-attr")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs."0".hello = derivationStrict {
            name = "numeric-attr";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."4294967295".hello = derivationStrict {
            name = "max-u32-attr";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."4294967296".hello = derivationStrict {
            name = "u32-overflow-attr";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let error = native
        .instantiate(&file, "pkgs.0.hello")
        .expect_err("numeric selection-path segments should require list values");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message }) if message.contains("expected list")
        ),
        "unexpected error: {error:?}"
    );

    let error = native
        .instantiate(&file, "pkgs.4294967295.hello")
        .expect_err("u32::MAX numeric selection-path segments should require list values");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message }) if message.contains("expected list")
        ),
        "unexpected error: {error:?}"
    );

    let path = native.instantiate(&file, "pkgs.4294967296.hello")?;
    assert!(path.to_string_lossy().ends_with("-u32-overflow-attr.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_does_not_auto_call_selected_drv_path_value() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-callable-drv-path")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          real = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        in {
          pkgs.hello.drvPath = { }: real.drvPath;
        }"#,
    )?;

    let error = native
        .instantiate(&file, "pkgs.hello")
        .expect_err("native -A traversal must not auto-call the selected drvPath value");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message })
                if message.contains("did not produce a string drvPath")
        ),
        "unexpected error: {error:?}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_does_not_auto_call_plain_lambda_files() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("aos-nix-native-instantiate-plain-lambda")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"x: {
          pkgs.hello = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let error = native
        .instantiate(&file, "pkgs.hello")
        .expect_err("plain lambdas should not be auto-called by native -A traversal");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { .. })
        ),
        "unexpected error: {error:?}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_attr_path_selector_matches_selection_path_syntax() -> Result<()> {
    for attr in [
        ".pkgs",
        ".",
        "pkgs..",
        "pkgs..hello",
        r#"pkgs."".hello"#,
        r#"pkgs.""."#,
    ] {
        let error = attr_path_selector(attr).expect_err("invalid attr path should fail");
        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { .. })
        ));
    }

    assert_eq!(attr_path_selector("")?, "");
    assert_eq!(attr_path_selector(r#""""#)?, "");
    assert_eq!(attr_path_selector("pkgs.")?, r#"."pkgs""#);
    assert_eq!(attr_path_selector(r#"pkgs."""#)?, r#"."pkgs""#);
    assert_eq!(
        attr_path_selector("or.foo-bar.x'")?,
        r#"."or"."foo-bar"."x'""#
    );
    assert_eq!(
        attr_path_selector("let.a/b+ c;hello")?,
        r#"."let"."a/b+ c;hello""#
    );
    assert_eq!(attr_path_selector(r#"a"."b"#)?, r#"."a.b""#);
    assert_eq!(attr_path_selector("\"\"a")?, r#"."a""#);
    assert_eq!(
        attr_path_selector(r#""pkgs.with.dot".hello"#)?,
        r#"."pkgs.with.dot"."hello""#
    );
    Ok(())
}

#[test]
fn native_instantiation_string_literals_escape_interpolation_openers() -> Result<()> {
    assert_eq!(nix_string_literal(b"/tmp/${name}")?, r#""/tmp/\${name}""#);
    assert_eq!(
        parse_attr_path_segments(r#""a${b}".hello"#)?,
        vec![b"a${b}".to_vec(), b"hello".to_vec()]
    );
    assert_eq!(
        parse_attr_path_segments(r#""a\${b}".hello"#)?,
        vec![b"a\\${b}".to_vec(), b"hello".to_vec()]
    );
    assert_eq!(
        parse_attr_path_segments(r#""a\n".hello"#)?,
        vec![b"a\\n".to_vec(), b"hello".to_vec()]
    );
    Ok(())
}
