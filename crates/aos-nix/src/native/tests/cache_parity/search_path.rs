//! Configured search-path closure parity canaries.

use super::*;

#[test]
fn native_file_cache_parity_harness_covers_configured_search_path_input() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-search-path");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    let search_root = root.join("search-root");
    let found_tree = search_root.join("source");
    fs::create_dir_all(&dir)?;
    fs::create_dir_all(&found_tree)?;
    let payload = b"native search-path source payload";
    fs::write(found_tree.join("payload.txt"), payload)?;
    let found_path = path_bytes(&fs::canonicalize(&found_tree)?)?;
    let search_root_path = path_bytes(&fs::canonicalize(&search_root)?)?;
    let search_path_trace = vec![ImpureInputFingerprint::path_exists_with_mode(
        found_path.as_slice(),
        ImpureInputMode::FindFileCandidate,
        true,
    )?];

    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
        in {
          pkgs = rec {
            found = <pkg/source>;
            source = b.path {
              path = found;
              name = "native-search-path-source";
              recursive = true;
            };
            searchPath = derivationStrict {
              name = "native-search-path";
              system = "x86_64-linux";
              builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              args = [ source ];
            };
          };
        }"#,
    )?;

    let report = native_file_closure_cache_parity_allowing_aggregate_cache_activity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.searchPath",
        |options| {
            options.add_nix_path_entry(b"pkg".to_vec(), search_root_path.clone())?;
            Ok(())
        },
    )?;
    assert_eq!(report.uncached.drvs().len(), 1);
    assert!(
        report.uncached.root().starts_with(&store),
        "{}",
        report.uncached.root().display()
    );
    assert_drv_aterm_contains_all(
        "configured search-path native closure",
        &report.uncached,
        &[
            ("derivation name", b"native-search-path"),
            ("source path store name", b"native-search-path-source"),
        ],
    );
    assert_eq!(report.uncached_stats.cache_hits(), 0);
    assert_eq!(report.uncached_stats.cache_misses(), 1);
    assert_eq!(report.disabled_stats.cache_hits(), 0);
    assert_eq!(report.disabled_stats.cache_misses(), 1);
    assert!(
        report.cache_miss_stats.cache_misses() > 0,
        "cache-on miss should report the configured search-path lookup-cache miss"
    );

    assert_file_artifact_written(&root, &persist_root, &file)?;
    let mut canaries = persistent_force_cache_surface_canaries(&persist_root)?;
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "configured search-path root file",
        &file,
    )?);
    canaries.extend(impure_trace_surface_canaries(
        "configured search-path trace",
        &search_path_trace,
    ));
    canaries.extend(durable_hash_surface_canaries(
        "configured search-path payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(payload),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "configured search-path resolved path",
        context_free_nix_string_xxh3(found_path.as_slice()),
    ));
    for (surface_name, closure) in [
        ("uncached configured search-path closure", &report.uncached),
        (
            "cache-miss configured search-path closure",
            &report.cache_miss,
        ),
        (
            "second cache-on configured search-path closure",
            &report.cache_second,
        ),
        (
            "persistent-hit configured search-path closure",
            &report.persistent_hit,
        ),
        (
            "disabled configured search-path closure",
            &report.disabled_with_persist_root,
        ),
    ] {
        assert_native_closure_surfaces_do_not_contain_canaries(surface_name, closure, &canaries);
    }

    Ok(())
}
