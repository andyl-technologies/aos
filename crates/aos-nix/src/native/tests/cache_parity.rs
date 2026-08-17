//! Reusable native cache-off/cache-on `.drv` closure parity tests.

mod split;

use super::*;
use crate::cache::{
    CachedExpressionValue, DirEntryInput, DurableBlake3Hash, FileTypeForInput,
    ImpureInputFingerprint, ImpureInputMode, ParseCache, ParseFileKey, PersistCache,
    PersistFileArtifactKey, PersistNodeMetadataKey, ValueHash,
};

mod ambient_inputs;
mod current_system;
mod search_path;
mod stale_metadata;

#[test]
fn native_file_cache_parity_harness_covers_empty_foldl_update_regression() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-foldl-update");
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
          subdirs = [];
          filePackages = {
            zlib = derivationStrict {
              name = "foldl-update-zlib";
              system = "x86_64-linux";
              builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            };
          };
          subdirPackages = builtins.foldl'
            (acc: subdir: acc // { ${subdir} = true; })
            {}
            subdirs;
        in {
          pkgs = filePackages // subdirPackages;
        }"#,
    )?;

    let report =
        native_file_closure_cache_parity(&root, &store, &persist_root, &file, "pkgs.zlib", |_| {
            Ok(())
        })?;
    assert_eq!(report.uncached.drvs().len(), 1);
    assert!(
        report.uncached.root().starts_with(&store),
        "{}",
        report.uncached.root().display()
    );
    assert_eq!(report.cache_miss, report.uncached);
    assert_eq!(report.cache_second, report.uncached);
    assert_eq!(report.persistent_hit, report.uncached);
    assert_eq!(report.disabled_with_persist_root, report.uncached);
    let _observed_cache_activity = (
        report.cache_miss_stats.force_cache_hits(),
        report.cache_miss_stats.force_cache_misses(),
        report.cache_second_stats.force_cache_hits(),
        report.cache_second_stats.force_cache_misses(),
        report.persistent_hit_stats.force_cache_hits(),
        report.persistent_hit_stats.force_cache_misses(),
    );

    let source = fs::read(&file)?;
    let realpath = fs::canonicalize(&file)?;
    let parse_key = ParseCache::new(root.join("cache-miss-parse")).key_for_source(&source);
    let file_key = ParseFileKey::for_source(&realpath, &source);
    let mut canaries = durable_hash_surface_canaries(
        "foldl update file-root parse-cache BLAKE3",
        parse_key.as_durable_hash(),
    );
    canaries.extend(durable_hash_surface_canaries(
        "foldl update file-root content BLAKE3",
        file_key.content_hash().as_durable_hash(),
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached foldl update closure",
        &report.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cache-miss foldl update closure",
        &report.cache_miss,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "second cache-on foldl update closure",
        &report.cache_second,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit foldl update closure",
        &report.persistent_hit,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "disabled foldl update closure",
        &report.disabled_with_persist_root,
        &canaries,
    );

    Ok(())
}

#[test]
fn native_file_cache_parity_harness_covers_derivation_side_record_reuse() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-derivation-side-records");
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
          base = derivationStrict {
            name = "native-side-record-base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = "same";
          };
          sibling = derivationStrict {
            name = "native-side-record-sibling";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            env = "same";
          };
        in {
          pkgs.sideRecord = derivationStrict {
            name = "native-side-record-downstream";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            input = base.out;
            other = sibling.drvPath;
          };
        }"#,
    )?;

    let report = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.sideRecord",
        |_| Ok(()),
    )?;
    assert_eq!(report.uncached.drvs().len(), 3);
    assert!(
        report.uncached.root().starts_with(&store),
        "{}",
        report.uncached.root().display()
    );
    assert_drv_aterm_contains_all(
        "native derivation side-record closure",
        &report.uncached,
        &[
            ("base derivation name", b"native-side-record-base"),
            ("sibling derivation name", b"native-side-record-sibling"),
            (
                "downstream derivation name",
                b"native-side-record-downstream",
            ),
        ],
    );
    assert_eq!(report.uncached_stats.derivation_aterm_path_reuses(), 0);
    assert_eq!(
        report.uncached_stats.static_derivation_output_path_reuses(),
        0
    );
    assert_eq!(report.cache_miss_stats.derivation_aterm_path_reuses(), 0);
    assert_eq!(
        report
            .cache_miss_stats
            .static_derivation_output_path_reuses(),
        0
    );
    assert!(report.cache_miss_stats.derivation_hash_calculations() > 0);
    assert!(report.cache_miss_stats.derivation_text_path_calculations() > 0);
    assert_eq!(report.cache_second_stats.derivation_aterm_path_reuses(), 3);
    assert_eq!(
        report
            .cache_second_stats
            .static_derivation_output_path_reuses(),
        3
    );
    assert_eq!(report.cache_second_stats.derivation_hash_calculations(), 0);
    assert_eq!(
        report
            .cache_second_stats
            .derivation_text_path_calculations(),
        0
    );
    assert_eq!(
        report.persistent_hit_stats.derivation_aterm_path_reuses(),
        3
    );
    assert_eq!(
        report
            .persistent_hit_stats
            .static_derivation_output_path_reuses(),
        3
    );
    assert_eq!(
        report.persistent_hit_stats.derivation_hash_calculations(),
        0
    );
    assert_eq!(
        report
            .persistent_hit_stats
            .derivation_text_path_calculations(),
        0
    );
    assert_eq!(
        report.disabled_stats.static_derivation_output_path_reuses(),
        0
    );
    assert_eq!(report.disabled_stats.derivation_aterm_path_reuses(), 0);
    assert!(report.disabled_stats.derivation_hash_calculations() > 0);
    assert!(report.disabled_stats.derivation_text_path_calculations() > 0);

    Ok(())
}

#[test]
fn native_file_cache_parity_harness_covers_filesystem_impure_inputs() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-fs-inputs");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    let scan_dir = dir.join("scan");
    fs::create_dir_all(scan_dir.join("subdir"))?;
    fs::write(dir.join("dep.nix"), r#"{ suffix = "dep"; }"#)?;
    fs::write(dir.join("payload.txt"), b"cache parity payload\n")?;
    fs::write(scan_dir.join("nested.txt"), b"nested\n")?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
          dep = import ./dep.nix;
          payload = b.readFile ./payload.txt;
          digest = b.hashFile "sha256" ./payload.txt;
          entries = b.attrNames (b.readDir ./scan);
          fileType = b.readFileType ./scan/nested.txt;
          exists = if b.pathExists ./scan/nested.txt then "present" else "missing";
        in {
          pkgs.fsInputs = derivationStrict {
            name = "filesystem-inputs-${dep.suffix}";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [
              dep.suffix
              payload
              digest
              fileType
              exists
            ] ++ entries;
          };
        }"#,
    )?;

    let report = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.fsInputs",
        |_| Ok(()),
    )?;
    assert_eq!(report.uncached.drvs().len(), 1);
    assert!(
        report.uncached.root().starts_with(&store),
        "{}",
        report.uncached.root().display()
    );
    assert_eq!(report.cache_miss, report.uncached);
    assert_eq!(report.cache_second, report.uncached);
    assert_eq!(report.persistent_hit, report.uncached);
    assert_eq!(report.disabled_with_persist_root, report.uncached);
    assert_drv_aterm_contains_all(
        "filesystem-input uncached closure",
        &report.uncached,
        &[
            ("imported suffix", b"dep"),
            ("readFile payload", b"cache parity payload"),
            (
                "hashFile sha256 digest",
                b"0b7222b9a1df6aed32c39f4a7de551344fe360e784ecf607e7b91b8ac29c7c87",
            ),
            ("readFileType result", b"regular"),
            ("pathExists result branch", b"present"),
            ("readDir regular entry", b"nested.txt"),
            ("readDir directory entry", b"subdir"),
        ],
    );
    assert!(
        report.cache_miss_stats.cache_misses() > 0,
        "cache-on miss should report import parse-cache miss activity"
    );
    assert!(
        report.persistent_hit_stats.cache_hits() > 0,
        "fresh persistent-hit run should hydrate imported parse artifacts"
    );

    assert_file_artifact_written(&root, &persist_root, &file)?;
    let dep_file = dir.join("dep.nix");
    assert_file_artifact_written(&root, &persist_root, &dep_file)?;

    let mut canaries = file_parse_artifact_surface_canaries(&root, "filesystem root file", &file)?;
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "filesystem imported file",
        &dep_file,
    )?);
    canaries.extend(filesystem_input_surface_canaries(&dir, &scan_dir)?);
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached filesystem-input closure",
        &report.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cache-miss filesystem-input closure",
        &report.cache_miss,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "second cache-on filesystem-input closure",
        &report.cache_second,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit filesystem-input closure",
        &report.persistent_hit,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "disabled filesystem-input closure",
        &report.disabled_with_persist_root,
        &canaries,
    );

    Ok(())
}

#[test]
fn native_file_cache_parity_harness_covers_source_path_inputs() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-source-path");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let payload_file = dir.join("payload.txt");
    let payload = b"native-source-path-payload";
    fs::write(&payload_file, payload)?;
    let payload_realpath = fs::canonicalize(&payload_file)?;
    let payload_path = path_bytes(&payload_realpath)?;
    let read_file_trace = vec![ImpureInputFingerprint::read_file(
        payload_path.as_slice(),
        payload,
    )?];
    let hash_file_trace = vec![ImpureInputFingerprint::hash_file(
        payload_path.as_slice(),
        payload,
    )?];
    let read_file_type_trace = vec![ImpureInputFingerprint::read_file_type(
        payload_path.as_slice(),
        FileTypeForInput::Regular,
    )?];
    let path_exists_trace = vec![ImpureInputFingerprint::path_exists(
        payload_path.as_slice(),
        true,
    )?];
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
          source = b.path {
            path = ./payload.txt;
            name = "source-path-input";
            recursive = false;
            sha256 = "5d4cd33d7579d79f979fe3dea163b7e003f260e027797d511fa6ef3eba28333f";
          };
          payload = b.readFile ./payload.txt;
          digest = b.hashFile "sha256" ./payload.txt;
          fileType = b.readFileType ./payload.txt;
          exists = if b.pathExists ./payload.txt then "present" else "missing";
        in {
          pkgs.sourcePathInputs = derivationStrict {
            name = "source-path-${payload}";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [
              source
              payload
              digest
              fileType
              exists
            ];
          };
        }"#,
    )?;

    let report = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.sourcePathInputs",
        |_| Ok(()),
    )?;
    assert_eq!(report.uncached.drvs().len(), 1);
    assert!(
        report.uncached.root().starts_with(&store),
        "{}",
        report.uncached.root().display()
    );
    assert_drv_aterm_contains_all(
        "source-path input uncached closure",
        &report.uncached,
        &[
            ("source path store name", b"source-path-input"),
            ("source path payload", payload),
            (
                "source path sha256 digest",
                b"5d4cd33d7579d79f979fe3dea163b7e003f260e027797d511fa6ef3eba28333f",
            ),
            ("readFileType result", b"regular"),
            ("pathExists result branch", b"present"),
        ],
    );
    assert!(
        report.cache_miss_stats.force_cache_misses() > 0,
        "cache-on miss should report force-cache miss activity alongside the source-path input"
    );
    assert!(
        report.persistent_hit_stats.force_cache_hits() > 0,
        "persistent-hit run should replay forced payloads alongside the source-path input"
    );
    let read_file_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &read_file_trace,
        "source-path sibling readFile native closure",
    )?;
    let hash_file_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &hash_file_trace,
        "source-path sibling hashFile native closure",
    )?;
    let read_file_type_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &read_file_type_trace,
        "source-path sibling readFileType native closure",
    )?;
    let path_exists_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &path_exists_trace,
        "source-path sibling pathExists native closure",
    )?;
    for (label, key) in [
        ("source-path sibling readFile", read_file_trace_entry.0),
        ("source-path sibling hashFile", hash_file_trace_entry.0),
        (
            "source-path sibling readFileType",
            read_file_type_trace_entry.0,
        ),
        ("source-path sibling pathExists", path_exists_trace_entry.0),
    ] {
        assert!(
            report.persistent_hit_keys.contains(&key),
            "persistent-hit run should replay the {label} force-cache entry"
        );
    }

    assert_file_artifact_written(&root, &persist_root, &file)?;
    let mut canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "source-path root file",
        &file,
    )?);
    canaries.extend(durable_hash_surface_canaries(
        "source-path payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(payload),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "source-path input name",
        context_free_nix_string_xxh3(b"source-path-input"),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "source-path realpath",
        context_free_nix_string_xxh3(payload_path.as_slice()),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "source-path payload",
        context_free_nix_string_xxh3(payload),
    ));
    canaries.extend(impure_trace_surface_canaries(
        "source-path sibling readFile",
        &read_file_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "source-path sibling hashFile",
        &hash_file_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "source-path sibling readFileType",
        &read_file_type_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "source-path sibling pathExists",
        &path_exists_trace,
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "uncached source-path input closure",
        &report.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "cache-miss source-path input closure",
        &report.cache_miss,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "second cache-on source-path input closure",
        &report.cache_second,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "persistent-hit source-path input closure",
        &report.persistent_hit,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "disabled source-path input closure",
        &report.disabled_with_persist_root,
        &canaries,
    );

    Ok(())
}

fn assert_drv_aterm_contains_all(
    closure_name: &str,
    closure: &NativeDrvClosure,
    needles: &[(&str, &[u8])],
) {
    let root_bytes = closure
        .drvs()
        .get(closure.root())
        .unwrap_or_else(|| panic!("{} root .drv bytes are recorded", closure_name));
    for (needle_name, needle) in needles {
        assert!(
            contains_bytes(root_bytes, needle),
            "{} did not contain {} bytes {:?}: {:?}",
            closure_name,
            needle_name,
            needle,
            root_bytes
        );
    }
}

fn assert_drv_aterm_lacks_all(
    closure_name: &str,
    closure: &NativeDrvClosure,
    needles: &[(&str, &[u8])],
) {
    let root_bytes = closure
        .drvs()
        .get(closure.root())
        .unwrap_or_else(|| panic!("{} root .drv bytes are recorded", closure_name));
    for (needle_name, needle) in needles {
        assert!(
            !contains_bytes(root_bytes, needle),
            "{} unexpectedly contained {} bytes {:?}: {:?}",
            closure_name,
            needle_name,
            needle,
            root_bytes
        );
    }
}

fn assert_file_artifact_written(root: &Path, persist_root: &Path, file: &Path) -> Result<()> {
    let source = fs::read(file)?;
    let realpath = fs::canonicalize(file)?;
    let parse_cache = ParseCache::new(root.join("cache-miss-parse"));
    let parse_key = parse_cache.key_for_source(&source);
    assert!(
        parse_cache.entry_for_key(parse_key).is_complete(),
        "cache-on miss should populate the local parse cache for {}",
        file.display()
    );
    let file_key = ParseFileKey::for_source(&realpath, &source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    assert!(
        PersistCache::open(persist_root)?
            .lookup_file_artifact(file_artifact_key)?
            .is_some(),
        "cache-on miss should write a durable parse artifact for {}",
        file.display()
    );
    Ok(())
}

fn instantiate_file_closure_with_source_parse_hit(
    parse_root: &Path,
    options: TreeWalkOptions,
    file: &Path,
    attr: &str,
    context: &str,
) -> Result<(NativeDrvClosure, crate::eval::EvalStats)> {
    let observed_hits = Arc::new(Mutex::new(Vec::new()));
    let observed_hits_for_hook = Arc::clone(&observed_hits);
    let mut native = NixNative::with_options(0, options)?;
    native.set_persistent_parse_hit_hook(move |hit| {
        observed_hits_for_hook
            .lock()
            .expect("persistent parse hit observations lock")
            .push(hit);
    });
    let result = instantiate_file_closure_with_stats(&native, file, attr)?;
    assert_eq!(
        observed_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .clone(),
        vec![NativePersistentParseHit::Source],
        "{context} should hydrate the unchanged file root from the durable source artifact"
    );
    assert!(
        ParseCache::new(parse_root)
            .entry_for_source(&fs::read(file)?)
            .is_complete(),
        "{context} should hydrate the fresh parse-cache entry"
    );
    Ok(result)
}

fn file_parse_artifact_surface_canaries(
    root: &Path,
    label: &str,
    file: &Path,
) -> Result<Vec<(String, Vec<u8>)>> {
    let source = fs::read(file)?;
    let realpath = fs::canonicalize(file)?;
    let parse_key = ParseCache::new(root.join("cache-miss-parse")).key_for_source(&source);
    let file_key = ParseFileKey::for_source(&realpath, &source);
    let mut canaries = durable_hash_surface_canaries(
        &format!("{label} parse-cache BLAKE3"),
        parse_key.as_durable_hash(),
    );
    canaries.extend(durable_hash_surface_canaries(
        &format!("{label} content BLAKE3"),
        file_key.content_hash().as_durable_hash(),
    ));
    Ok(canaries)
}

fn filesystem_input_surface_canaries(
    dir: &Path,
    scan_dir: &Path,
) -> Result<Vec<(String, Vec<u8>)>> {
    let dep_file = fs::canonicalize(dir.join("dep.nix"))?;
    let payload_file = fs::canonicalize(dir.join("payload.txt"))?;
    let nested_file = fs::canonicalize(scan_dir.join("nested.txt"))?;
    let scan_dir = fs::canonicalize(scan_dir)?;
    let dep_source = fs::read(&dep_file)?;
    let payload = fs::read(&payload_file)?;
    let mut canaries = Vec::new();
    extend_impure_input_canaries(
        &mut canaries,
        "filesystem import dep.nix",
        ImpureInputFingerprint::import(path_bytes(&dep_file)?.as_slice(), &dep_source)?,
    );
    extend_impure_input_canaries(
        &mut canaries,
        "filesystem readFile payload.txt",
        ImpureInputFingerprint::read_file(path_bytes(&payload_file)?.as_slice(), &payload)?,
    );
    extend_impure_input_canaries(
        &mut canaries,
        "filesystem hashFile payload.txt",
        ImpureInputFingerprint::hash_file(path_bytes(&payload_file)?.as_slice(), &payload)?,
    );
    extend_impure_input_canaries(
        &mut canaries,
        "filesystem readDir scan",
        ImpureInputFingerprint::read_dir(
            path_bytes(&scan_dir)?.as_slice(),
            [
                DirEntryInput::new(b"nested.txt", FileTypeForInput::Regular),
                DirEntryInput::new(b"subdir", FileTypeForInput::Directory),
            ],
        )?,
    );
    extend_impure_input_canaries(
        &mut canaries,
        "filesystem readFileType nested.txt",
        ImpureInputFingerprint::read_file_type(
            path_bytes(&nested_file)?.as_slice(),
            FileTypeForInput::Regular,
        )?,
    );
    extend_impure_input_canaries(
        &mut canaries,
        "filesystem pathExists nested.txt",
        ImpureInputFingerprint::path_exists(path_bytes(&nested_file)?.as_slice(), true)?,
    );
    Ok(canaries)
}

fn payload_impure_input_surface_canaries(
    label: &str,
    payload_file: &Path,
    payload: &[u8],
) -> Result<Vec<(String, Vec<u8>)>> {
    let payload_file = fs::canonicalize(payload_file)?;
    let payload_path = path_bytes(&payload_file)?;
    let mut canaries = Vec::new();
    extend_impure_input_canaries(
        &mut canaries,
        &format!("{label} readFile"),
        ImpureInputFingerprint::read_file(payload_path.as_slice(), payload)?,
    );
    extend_impure_input_canaries(
        &mut canaries,
        &format!("{label} hashFile"),
        ImpureInputFingerprint::hash_file(payload_path.as_slice(), payload)?,
    );
    Ok(canaries)
}

fn assert_persistent_force_cache_trace_log_contains(
    persist_root: &Path,
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> Result<(PersistNodeMetadataKey, ValueHash)> {
    let expected = expected_trace
        .iter()
        .map(|input| {
            input
                .as_cacheable()
                .unwrap_or_else(|| panic!("{context} expected trace should be cacheable"))
                .clone()
        })
        .collect::<Vec<_>>();
    let persist = PersistCache::open(persist_root)?;
    let metadata_entries = persist.node_metadata_index().latest_entries()?;
    let trace_entries = persist.node_trace_log().latest_entries()?;
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
    Ok(live_matches[0])
}

fn extend_impure_input_canaries(
    canaries: &mut Vec<(String, Vec<u8>)>,
    label: &str,
    fingerprint: ImpureInputFingerprint,
) {
    let Some(cacheable) = fingerprint.as_cacheable() else {
        return;
    };
    canaries.extend(durable_hash_surface_canaries(
        &format!("{label} identity BLAKE3"),
        cacheable.identity().hash().as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        &format!("{label} observation BLAKE3"),
        cacheable.observation_hash().as_durable_hash(),
    ));
}

fn impure_trace_surface_canaries(
    label: &str,
    trace: &[ImpureInputFingerprint],
) -> Vec<(String, Vec<u8>)> {
    let mut canaries = Vec::new();
    for (index, fingerprint) in trace.iter().enumerate() {
        extend_impure_input_canaries(
            &mut canaries,
            &format!("{label} input {index}"),
            fingerprint.clone(),
        );
    }
    canaries
}
