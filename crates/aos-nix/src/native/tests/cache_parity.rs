//! Reusable native cache-off/cache-on `.drv` closure parity tests.

use super::*;
use crate::cache::{
    DirEntryInput, DurableBlake3Hash, FileTypeForInput, ImpureInputFingerprint, ParseCache,
    ParseFileKey, PersistCache, PersistFileArtifactKey,
};

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
    assert_eq!(report.uncached_stats.force_cache_hits(), 0);
    assert_eq!(report.uncached_stats.force_cache_misses(), 0);
    assert_eq!(report.disabled_stats.force_cache_hits(), 0);
    assert_eq!(report.disabled_stats.force_cache_misses(), 0);
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
        DurableBlake3Hash::from_bytes(parse_key.as_bytes()),
    );
    canaries.extend(durable_hash_surface_canaries(
        "foldl update file-root content BLAKE3",
        file_key.content_hash(),
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
    assert_eq!(report.uncached_stats.force_cache_hits(), 0);
    assert_eq!(report.uncached_stats.force_cache_misses(), 0);
    assert_eq!(report.disabled_stats.force_cache_hits(), 0);
    assert_eq!(report.disabled_stats.force_cache_misses(), 0);
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
        DurableBlake3Hash::from_bytes(parse_key.as_bytes()),
    );
    canaries.extend(durable_hash_surface_canaries(
        &format!("{label} content BLAKE3"),
        file_key.content_hash(),
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
        cacheable.identity().hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        &format!("{label} observation BLAKE3"),
        cacheable.observation_hash(),
    ));
}
