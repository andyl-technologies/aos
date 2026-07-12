//! Split-out `cache_parity.rs` test group (split).

use super::*;

#[test]
fn native_file_cache_parity_harness_covers_stale_source_path_input() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-stale-source-path");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let payload_file = dir.join("payload.txt");
    let original_payload = b"stale source path original payload";
    let changed_payload = b"stale source path changed payload";
    fs::write(&payload_file, original_payload)?;
    let payload_realpath = fs::canonicalize(&payload_file)?;
    let payload_path = path_bytes(&payload_realpath)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
          source = b.path {
            path = ./payload.txt;
            name = "stale-source-path-input";
            recursive = false;
          };
        in {
          pkgs.staleSourcePath = derivationStrict {
            name = "stale-source-path-derivation";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [ source ];
          };
        }"#,
    )?;

    let original = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.staleSourcePath",
        |_| Ok(()),
    )?;
    assert_eq!(original.uncached.drvs().len(), 1);
    assert_drv_aterm_contains_all(
        "original stale source-path closure",
        &original.uncached,
        &[("source path store name", b"stale-source-path-input")],
    );
    assert_drv_aterm_lacks_all(
        "original stale source-path closure",
        &original.uncached,
        &[
            ("original source payload", original_payload),
            ("changed source payload", changed_payload),
        ],
    );

    fs::write(&payload_file, changed_payload)?;

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
        "pkgs.staleSourcePath",
    )?;
    assert_eq!(uncached_changed_stats.force_cache_hits(), 0);
    assert_eq!(uncached_changed_stats.force_cache_misses(), 0);
    assert_ne!(
        uncached_changed, original.uncached,
        "changed builtins.path payload must change the uncached .drv closure"
    );
    assert_ne!(
        uncached_changed.root(),
        original.uncached.root(),
        "changed builtins.path payload must change the root .drv path"
    );
    assert_drv_aterm_contains_all(
        "changed uncached stale source-path closure",
        &uncached_changed,
        &[("source path store name", b"stale-source-path-input")],
    );
    assert_drv_aterm_lacks_all(
        "changed uncached stale source-path closure",
        &uncached_changed,
        &[
            ("original source payload", original_payload),
            ("changed source payload", changed_payload),
        ],
    );

    let stale_cached_parse_root = root.join("stale-source-path-parse");
    let (stale_cached, _stale_cached_stats) = instantiate_file_closure_with_source_parse_hit(
        &stale_cached_parse_root,
        options_for(Some(&stale_cached_parse_root), true, true)?,
        &file,
        "pkgs.staleSourcePath",
        "stale source-path run",
    )?;
    assert_eq!(
        stale_cached, uncached_changed,
        "stale persistent source-path payloads must recompute to the changed closure"
    );
    assert_ne!(
        stale_cached, original.uncached,
        "stale persistent source-path payloads must not replay the original closure"
    );

    let changed_hit_parse_root = root.join("changed-source-path-hit-parse");
    let (changed_hit, _changed_hit_stats) = instantiate_file_closure_with_source_parse_hit(
        &changed_hit_parse_root,
        options_for(Some(&changed_hit_parse_root), true, true)?,
        &file,
        "pkgs.staleSourcePath",
        "post-recompute source-path run",
    )?;
    assert_eq!(
        changed_hit, uncached_changed,
        "post-recompute persistent source-path run should preserve the changed closure"
    );

    let mut canaries = persistent_force_cache_surface_canaries(&persist_root)?;
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "stale source-path root file",
        &file,
    )?);
    canaries.extend(durable_hash_surface_canaries(
        "original stale source-path payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(original_payload),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "changed stale source-path payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(changed_payload),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "stale source-path input name",
        context_free_nix_string_xxh3(b"stale-source-path-input"),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "stale source-path realpath",
        context_free_nix_string_xxh3(payload_path.as_slice()),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "original stale source-path payload",
        context_free_nix_string_xxh3(original_payload),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "changed stale source-path payload",
        context_free_nix_string_xxh3(changed_payload),
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "original stale source-path closure",
        &original.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed uncached stale source-path closure",
        &uncached_changed,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "stale cached source-path closure",
        &stale_cached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed persistent source-path hit closure",
        &changed_hit,
        &canaries,
    );

    Ok(())
}

#[test]
fn native_file_cache_parity_harness_covers_filtered_source_path_inputs() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-filtered-source-path");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let tree = dir.join("filtered-source-tree");
    fs::create_dir_all(&tree)?;
    let kept_file = tree.join("kept.txt");
    let ignored_file = tree.join("ignored.txt");
    let original_kept = b"filtered source original kept payload";
    let changed_kept = b"filtered source changed kept payload";
    let original_ignored = b"filtered source original ignored payload";
    let changed_ignored = b"filtered source changed ignored payload";
    fs::write(&kept_file, original_kept)?;
    fs::write(&ignored_file, original_ignored)?;
    let kept_realpath = fs::canonicalize(&kept_file)?;
    let ignored_realpath = fs::canonicalize(&ignored_file)?;
    let kept_path = path_bytes(&kept_realpath)?;
    let ignored_path = path_bytes(&ignored_realpath)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
          keep = path: type:
            type != "directory" && b.baseNameOf path == "kept.txt";
          source = b.filterSource keep ./filtered-source-tree;
        in {
          pkgs.filteredSourcePath = derivationStrict {
            name = "filtered-source-derivation";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [ source ];
          };
        }"#,
    )?;

    let original = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.filteredSourcePath",
        |_| Ok(()),
    )?;
    assert_eq!(original.uncached.drvs().len(), 1);
    assert_drv_aterm_contains_all(
        "original filtered source-path closure",
        &original.uncached,
        &[("filtered source path store name", b"filtered-source-tree")],
    );
    assert_drv_aterm_lacks_all(
        "original filtered source-path closure",
        &original.uncached,
        &[
            ("original kept payload", original_kept),
            ("changed kept payload", changed_kept),
            ("original ignored payload", original_ignored),
            ("changed ignored payload", changed_ignored),
        ],
    );

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

    fs::write(&ignored_file, changed_ignored)?;

    let (uncached_ignored_changed, uncached_ignored_changed_stats) =
        instantiate_file_closure_with_stats(
            &NixNative::with_options(0, options_for(None, false, false)?)?,
            &file,
            "pkgs.filteredSourcePath",
        )?;
    assert_eq!(uncached_ignored_changed_stats.force_cache_hits(), 0);
    assert_eq!(uncached_ignored_changed_stats.force_cache_misses(), 0);
    assert_eq!(
        uncached_ignored_changed, original.uncached,
        "changing an excluded filtered-source payload must not change the uncached .drv closure"
    );

    let ignored_cached_parse_root = root.join("ignored-filtered-source-parse");
    let (ignored_cached, _ignored_cached_stats) = instantiate_file_closure_with_source_parse_hit(
        &ignored_cached_parse_root,
        options_for(Some(&ignored_cached_parse_root), true, true)?,
        &file,
        "pkgs.filteredSourcePath",
        "excluded filtered-source change run",
    )?;
    assert_eq!(
        ignored_cached, original.uncached,
        "changing an excluded filtered-source payload must preserve the cached closure surface"
    );

    fs::write(&kept_file, changed_kept)?;

    let (uncached_kept_changed, uncached_kept_changed_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, options_for(None, false, false)?)?,
        &file,
        "pkgs.filteredSourcePath",
    )?;
    assert_eq!(uncached_kept_changed_stats.force_cache_hits(), 0);
    assert_eq!(uncached_kept_changed_stats.force_cache_misses(), 0);
    assert_ne!(
        uncached_kept_changed, original.uncached,
        "changing an included filtered-source payload must change the uncached .drv closure"
    );
    assert_ne!(
        uncached_kept_changed.root(),
        original.uncached.root(),
        "changing an included filtered-source payload must change the root .drv path"
    );
    assert_drv_aterm_contains_all(
        "changed kept filtered source-path closure",
        &uncached_kept_changed,
        &[("filtered source path store name", b"filtered-source-tree")],
    );
    assert_drv_aterm_lacks_all(
        "changed kept filtered source-path closure",
        &uncached_kept_changed,
        &[
            ("original kept payload", original_kept),
            ("changed kept payload", changed_kept),
            ("original ignored payload", original_ignored),
            ("changed ignored payload", changed_ignored),
        ],
    );

    let kept_cached_parse_root = root.join("kept-filtered-source-parse");
    let (kept_cached, _kept_cached_stats) = instantiate_file_closure_with_source_parse_hit(
        &kept_cached_parse_root,
        options_for(Some(&kept_cached_parse_root), true, true)?,
        &file,
        "pkgs.filteredSourcePath",
        "included filtered-source changed run",
    )?;
    assert_eq!(
        kept_cached, uncached_kept_changed,
        "cached filtered-source evaluation must produce the changed included closure"
    );
    assert_ne!(
        kept_cached, original.uncached,
        "cached filtered-source evaluation must not preserve the original included closure"
    );

    let kept_hit_parse_root = root.join("kept-filtered-source-hit-parse");
    let (kept_hit, _kept_hit_stats) = instantiate_file_closure_with_source_parse_hit(
        &kept_hit_parse_root,
        options_for(Some(&kept_hit_parse_root), true, true)?,
        &file,
        "pkgs.filteredSourcePath",
        "post-recompute filtered-source run",
    )?;
    assert_eq!(
        kept_hit, uncached_kept_changed,
        "post-recompute persistent filtered-source run should preserve the changed included closure"
    );

    let mut canaries = persistent_force_cache_surface_canaries(&persist_root)?;
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "filtered source-path root file",
        &file,
    )?);
    let payload_canaries: [(&str, &[u8]); 4] = [
        ("original filtered-source kept payload", original_kept),
        ("changed filtered-source kept payload", changed_kept),
        ("original filtered-source ignored payload", original_ignored),
        ("changed filtered-source ignored payload", changed_ignored),
    ];
    for (label, payload) in payload_canaries {
        canaries.extend(durable_hash_surface_canaries(
            &format!("{label} BLAKE3 sentinel"),
            DurableBlake3Hash::for_bytes(payload),
        ));
        canaries.extend(hot_xxh3_surface_canaries(
            label,
            context_free_nix_string_xxh3(payload),
        ));
    }
    canaries.extend(hot_xxh3_surface_canaries(
        "filtered source-path store name",
        context_free_nix_string_xxh3(b"filtered-source-tree"),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "filtered source-path kept realpath",
        context_free_nix_string_xxh3(kept_path.as_slice()),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "filtered source-path ignored realpath",
        context_free_nix_string_xxh3(ignored_path.as_slice()),
    ));
    for (surface_name, closure) in [
        ("original filtered source-path closure", &original.uncached),
        (
            "ignored-change uncached filtered source-path closure",
            &uncached_ignored_changed,
        ),
        (
            "ignored-change cached filtered source-path closure",
            &ignored_cached,
        ),
        (
            "kept-change uncached filtered source-path closure",
            &uncached_kept_changed,
        ),
        (
            "kept-change cached filtered source-path closure",
            &kept_cached,
        ),
        ("kept-change hit filtered source-path closure", &kept_hit),
    ] {
        assert_native_closure_surfaces_do_not_contain_canaries(surface_name, closure, &canaries);
    }

    Ok(())
}

#[test]
fn native_file_cache_parity_harness_covers_stale_filesystem_impure_inputs() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-stale-fs-inputs");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let payload_file = dir.join("payload.txt");
    let original_payload = b"stale cache parity original payload";
    let changed_payload = b"stale cache parity changed payload";
    fs::write(&payload_file, original_payload)?;
    let payload_realpath = fs::canonicalize(&payload_file)?;
    let payload_path = path_bytes(&payload_realpath)?;
    let original_read_file_trace = vec![ImpureInputFingerprint::read_file(
        payload_path.as_slice(),
        original_payload,
    )?];
    let original_hash_file_trace = vec![ImpureInputFingerprint::hash_file(
        payload_path.as_slice(),
        original_payload,
    )?];
    let changed_read_file_trace = vec![ImpureInputFingerprint::read_file(
        payload_path.as_slice(),
        changed_payload,
    )?];
    let changed_hash_file_trace = vec![ImpureInputFingerprint::hash_file(
        payload_path.as_slice(),
        changed_payload,
    )?];
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
          payload = b.readFile ./payload.txt;
          digest = b.hashFile "sha256" ./payload.txt;
        in {
          pkgs.staleInputs = derivationStrict {
            name = "stale-filesystem-inputs";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [
              payload
              digest
            ];
          };
        }"#,
    )?;

    let original = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.staleInputs",
        |_| Ok(()),
    )?;
    assert_drv_aterm_contains_all(
        "original stale filesystem-input closure",
        &original.uncached,
        &[
            ("original readFile payload", original_payload),
            (
                "original hashFile sha256 digest",
                b"131d36d31162bbaadd5c662599d1c7c580bd1b03baa07a0a6bcd47c588e7f761",
            ),
        ],
    );
    let original_force_canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    let original_read_file_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &original_read_file_trace,
        "original stale readFile native closure",
    )?;
    let original_hash_file_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &original_hash_file_trace,
        "original stale hashFile native closure",
    )?;

    fs::write(&payload_file, changed_payload)?;

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
        "pkgs.staleInputs",
    )?;
    assert_eq!(uncached_changed_stats.force_cache_hits(), 0);
    assert_eq!(uncached_changed_stats.force_cache_misses(), 0);
    assert_ne!(
        uncached_changed, original.uncached,
        "changed filesystem payload must change the uncached .drv closure"
    );
    assert_drv_aterm_contains_all(
        "changed uncached stale filesystem-input closure",
        &uncached_changed,
        &[
            ("changed readFile payload", changed_payload),
            (
                "changed hashFile sha256 digest",
                b"2ac0b98f5db98ed3094bdd7529c7c81802f66b8cea09918f8df869204db0c87a",
            ),
        ],
    );
    assert_drv_aterm_lacks_all(
        "changed uncached stale filesystem-input closure",
        &uncached_changed,
        &[
            ("original readFile payload", original_payload),
            (
                "original hashFile sha256 digest",
                b"131d36d31162bbaadd5c662599d1c7c580bd1b03baa07a0a6bcd47c588e7f761",
            ),
        ],
    );

    let (stale_cached, stale_cached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(Some(&root.join("stale-cache-parse")), true, true)?,
        )?,
        &file,
        "pkgs.staleInputs",
    )?;
    assert_eq!(
        stale_cached, uncached_changed,
        "stale persistent impure-input payloads must recompute to the changed closure"
    );
    assert_ne!(
        stale_cached, original.uncached,
        "stale persistent impure-input payloads must not replay the original closure"
    );
    assert!(
        stale_cached_stats.force_cache_misses() > 0,
        "stale persistent impure-input payloads should miss before recomputing"
    );
    let changed_read_file_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_read_file_trace,
        "changed stale readFile native closure",
    )?;
    let changed_hash_file_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_hash_file_trace,
        "changed stale hashFile native closure",
    )?;
    assert_eq!(
        changed_read_file_trace_entry.0, original_read_file_trace_entry.0,
        "stale readFile recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_read_file_trace_entry.1, original_read_file_trace_entry.1,
        "stale readFile recomputation should materialize a changed force-cache value"
    );
    assert_eq!(
        changed_hash_file_trace_entry.0, original_hash_file_trace_entry.0,
        "stale hashFile recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_hash_file_trace_entry.1, original_hash_file_trace_entry.1,
        "stale hashFile recomputation should materialize a changed force-cache value"
    );

    let (changed_hit, changed_hit_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(Some(&root.join("changed-hit-parse")), true, true)?,
        )?,
        &file,
        "pkgs.staleInputs",
    )?;
    assert_eq!(
        changed_hit, uncached_changed,
        "post-recompute persistent run should preserve the changed closure"
    );
    assert!(
        changed_hit_stats.force_cache_hits() > 0,
        "post-recompute persistent run should replay changed force-cache payloads"
    );
    assert_eq!(
        changed_hit_stats.force_cache_misses(),
        0,
        "post-recompute persistent run should not recompute changed force-cache payloads"
    );
    assert_eq!(
        assert_persistent_force_cache_trace_log_contains(
            &persist_root,
            &changed_read_file_trace,
            "post-recompute stale readFile native closure",
        )?,
        changed_read_file_trace_entry,
        "post-recompute readFile reuse should keep the changed trace live"
    );
    assert_eq!(
        assert_persistent_force_cache_trace_log_contains(
            &persist_root,
            &changed_hash_file_trace,
            "post-recompute stale hashFile native closure",
        )?,
        changed_hash_file_trace_entry,
        "post-recompute hashFile reuse should keep the changed trace live"
    );

    let mut canaries = original_force_canaries;
    canaries.extend(persistent_force_cache_surface_canaries(&persist_root)?);
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "stale filesystem root file",
        &file,
    )?);
    canaries.extend(payload_impure_input_surface_canaries(
        "original stale filesystem payload",
        &payload_file,
        original_payload,
    )?);
    canaries.extend(payload_impure_input_surface_canaries(
        "changed stale filesystem payload",
        &payload_file,
        changed_payload,
    )?);
    assert_native_closure_surfaces_do_not_contain_canaries(
        "original stale filesystem-input closure",
        &original.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed uncached stale filesystem-input closure",
        &uncached_changed,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "stale cached filesystem-input closure",
        &stale_cached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "post-recompute cached filesystem-input closure",
        &changed_hit,
        &canaries,
    );

    Ok(())
}

