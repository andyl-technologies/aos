//! Reusable native cache-off/cache-on `.drv` closure parity tests.

use super::*;
use crate::cache::{DurableBlake3Hash, ParseCache, ParseFileKey};

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
