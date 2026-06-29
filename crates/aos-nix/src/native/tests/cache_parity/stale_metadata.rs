//! Stale metadata impure-input closure parity canaries.

use super::*;

#[test]
fn native_file_cache_parity_harness_covers_stale_metadata_impure_inputs() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-stale-metadata-inputs");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    let scan_dir = dir.join("scan");
    fs::create_dir_all(scan_dir.join("subdir"))?;
    let nested_path = scan_dir.join("nested.txt");
    let marker_path = scan_dir.join("vanished.txt");
    fs::write(&nested_path, b"nested\n")?;
    fs::write(&marker_path, b"present\n")?;

    let scan_path = path_bytes(&fs::canonicalize(&scan_dir)?)?;
    let nested_path_bytes = path_bytes(&nested_path)?;
    let marker_path_bytes = path_bytes(&marker_path)?;
    let original_read_dir_trace = vec![ImpureInputFingerprint::read_dir(
        scan_path.as_slice(),
        [
            DirEntryInput::new(b"nested.txt", FileTypeForInput::Regular),
            DirEntryInput::new(b"subdir", FileTypeForInput::Directory),
            DirEntryInput::new(b"vanished.txt", FileTypeForInput::Regular),
        ],
    )?];
    let original_read_file_type_trace = vec![ImpureInputFingerprint::read_file_type(
        nested_path_bytes.as_slice(),
        FileTypeForInput::Regular,
    )?];
    let original_path_exists_trace = vec![ImpureInputFingerprint::path_exists(
        marker_path_bytes.as_slice(),
        true,
    )?];
    let changed_read_dir_trace = vec![ImpureInputFingerprint::read_dir(
        scan_path.as_slice(),
        [
            DirEntryInput::new(b"nested.txt", FileTypeForInput::Directory),
            DirEntryInput::new(b"subdir", FileTypeForInput::Directory),
        ],
    )?];
    let changed_read_file_type_trace = vec![ImpureInputFingerprint::read_file_type(
        nested_path_bytes.as_slice(),
        FileTypeForInput::Directory,
    )?];
    let changed_path_exists_trace = vec![ImpureInputFingerprint::path_exists(
        marker_path_bytes.as_slice(),
        false,
    )?];

    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
          dirEntries = b.readDir ./scan;
          entries = b.attrNames dirEntries;
          readDirNestedType = "readdir-" + b.getAttr "nested.txt" dirEntries;
          fileType = b.readFileType ./scan/nested.txt;
          marker = if b.pathExists ./scan/vanished.txt then "exists-present" else "exists-missing";
        in {
          pkgs.staleMetadata = derivationStrict {
            name = "stale-metadata-inputs";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [
              fileType
              readDirNestedType
              marker
            ] ++ entries;
          };
        }"#,
    )?;

    let original = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.staleMetadata",
        |_| Ok(()),
    )?;
    assert_drv_aterm_contains_all(
        "original stale metadata-input closure",
        &original.uncached,
        &[
            ("original readFileType result", b"regular"),
            ("original readDir nested type", b"readdir-regular"),
            ("original pathExists branch", b"exists-present"),
            ("original readDir nested entry", b"nested.txt"),
            ("original readDir subdir entry", b"subdir"),
            ("original readDir vanished entry", b"vanished.txt"),
        ],
    );
    let original_force_canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    let original_read_dir_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &original_read_dir_trace,
        "original stale readDir native closure",
    )?;
    let original_read_file_type_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &original_read_file_type_trace,
        "original stale readFileType native closure",
    )?;
    let original_path_exists_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &original_path_exists_trace,
        "original stale pathExists native closure",
    )?;

    fs::remove_file(&marker_path)?;
    fs::remove_file(&nested_path)?;
    fs::create_dir(&nested_path)?;

    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let options_for =
        |parse_root: Option<&Path>, persist: bool, eval_cache_enabled: bool| -> Result<_> {
            let mut options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
            if let Some(parse_root) = parse_root {
                options.set_parse_cache_root(parse_root);
            } else {
                options.clear_parse_cache_root();
            }
            if persist {
                options.set_persist_cache_root(&persist_root);
            } else {
                options.clear_persist_cache_root();
            }
            options.set_eval_cache_enabled(eval_cache_enabled);
            Ok(options)
        };

    let (uncached_changed, uncached_changed_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, options_for(None, false, false)?)?,
        &file,
        "pkgs.staleMetadata",
    )?;
    assert_eq!(uncached_changed_stats.force_cache_hits(), 0);
    assert_eq!(uncached_changed_stats.force_cache_misses(), 0);
    assert_ne!(
        uncached_changed, original.uncached,
        "changed filesystem metadata must change the uncached .drv closure"
    );
    assert_drv_aterm_contains_all(
        "changed uncached stale metadata-input closure",
        &uncached_changed,
        &[
            ("changed readFileType result", b"directory"),
            ("changed readDir nested type", b"readdir-directory"),
            ("changed pathExists branch", b"exists-missing"),
            ("changed readDir nested entry", b"nested.txt"),
            ("changed readDir subdir entry", b"subdir"),
        ],
    );
    assert_drv_aterm_lacks_all(
        "changed uncached stale metadata-input closure",
        &uncached_changed,
        &[
            ("original readFileType result", b"regular"),
            ("original readDir nested type", b"readdir-regular"),
            ("original pathExists branch", b"exists-present"),
            ("original readDir vanished entry", b"vanished.txt"),
        ],
    );

    let (stale_cached, stale_cached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(Some(&root.join("stale-metadata-parse")), true, true)?,
        )?,
        &file,
        "pkgs.staleMetadata",
    )?;
    assert_eq!(
        stale_cached, uncached_changed,
        "stale persistent metadata inputs must recompute to the changed closure"
    );
    assert_ne!(
        stale_cached, original.uncached,
        "stale persistent metadata inputs must not replay the original closure"
    );
    assert!(
        stale_cached_stats.force_cache_misses() > 0,
        "stale persistent metadata inputs should miss before recomputing"
    );
    let changed_read_dir_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_read_dir_trace,
        "changed stale readDir native closure",
    )?;
    let changed_read_file_type_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_read_file_type_trace,
        "changed stale readFileType native closure",
    )?;
    let changed_path_exists_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_path_exists_trace,
        "changed stale pathExists native closure",
    )?;
    assert_eq!(
        changed_read_dir_trace_entry.0, original_read_dir_trace_entry.0,
        "stale readDir recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_read_dir_trace_entry.1, original_read_dir_trace_entry.1,
        "stale readDir recomputation should materialize a changed force-cache value"
    );
    assert_eq!(
        changed_read_file_type_trace_entry.0, original_read_file_type_trace_entry.0,
        "stale readFileType recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_read_file_type_trace_entry.1, original_read_file_type_trace_entry.1,
        "stale readFileType recomputation should materialize a changed force-cache value"
    );
    assert_eq!(
        changed_path_exists_trace_entry.0, original_path_exists_trace_entry.0,
        "stale pathExists recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_path_exists_trace_entry.1, original_path_exists_trace_entry.1,
        "stale pathExists recomputation should materialize a changed force-cache value"
    );

    let (changed_hit, changed_hit_stats, changed_hit_keys) =
        instantiate_file_closure_with_stats_and_hits(
            &NixNative::with_options(
                0,
                options_for(Some(&root.join("changed-metadata-hit-parse")), true, true)?,
            )?,
            &file,
            "pkgs.staleMetadata",
        )?;
    assert_eq!(
        changed_hit, uncached_changed,
        "post-recompute persistent metadata run should preserve the changed closure"
    );
    assert!(
        changed_hit_stats.force_cache_hits() >= 3,
        "post-recompute persistent metadata run should replay changed force-cache payloads"
    );
    for (key_name, key) in [
        ("readDir", changed_read_dir_trace_entry.0),
        ("readFileType", changed_read_file_type_trace_entry.0),
        ("pathExists", changed_path_exists_trace_entry.0),
    ] {
        assert!(
            changed_hit_keys.contains(&key),
            "post-recompute persistent metadata run should load the changed {key_name} force-cache metadata key"
        );
    }
    assert_eq!(
        assert_persistent_force_cache_trace_log_contains(
            &persist_root,
            &changed_read_dir_trace,
            "post-recompute stale readDir native closure",
        )?,
        changed_read_dir_trace_entry,
        "post-recompute readDir reuse should keep the changed trace live"
    );
    assert_eq!(
        assert_persistent_force_cache_trace_log_contains(
            &persist_root,
            &changed_read_file_type_trace,
            "post-recompute stale readFileType native closure",
        )?,
        changed_read_file_type_trace_entry,
        "post-recompute readFileType reuse should keep the changed trace live"
    );
    assert_eq!(
        assert_persistent_force_cache_trace_log_contains(
            &persist_root,
            &changed_path_exists_trace,
            "post-recompute stale pathExists native closure",
        )?,
        changed_path_exists_trace_entry,
        "post-recompute pathExists reuse should keep the changed trace live"
    );

    let mut canaries = original_force_canaries;
    canaries.extend(persistent_force_cache_surface_canaries(&persist_root)?);
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "stale metadata root file",
        &file,
    )?);
    canaries.extend(impure_trace_surface_canaries(
        "original stale metadata readDir",
        &original_read_dir_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "original stale metadata readFileType",
        &original_read_file_type_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "original stale metadata pathExists",
        &original_path_exists_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "changed stale metadata readDir",
        &changed_read_dir_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "changed stale metadata readFileType",
        &changed_read_file_type_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "changed stale metadata pathExists",
        &changed_path_exists_trace,
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "original stale metadata-input closure",
        &original.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed uncached stale metadata-input closure",
        &uncached_changed,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "stale cached metadata-input closure",
        &stale_cached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "post-recompute cached metadata-input closure",
        &changed_hit,
        &canaries,
    );

    Ok(())
}
