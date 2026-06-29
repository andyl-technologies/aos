//! Ambient impure-input closure parity canaries.

use super::*;

#[test]
fn native_file_cache_parity_harness_covers_get_env_impure_input() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-get-env");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;

    let env_name = b"AOS_NATIVE_FILE_CACHE_ENV";
    let original_env = b"env-payload".as_slice();
    let changed_env = b"changed-payload".as_slice();
    let original_trace = vec![ImpureInputFingerprint::get_env(
        env_name,
        Some(original_env),
    )?];
    let changed_trace = vec![ImpureInputFingerprint::get_env(
        env_name,
        Some(changed_env),
    )?];
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
          payload = b.getEnv "AOS_NATIVE_FILE_CACHE_ENV";
        in {
          pkgs.envInput = derivationStrict {
            name = "get-env-${payload}";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [
              payload
              "arg-${payload}"
            ];
          };
        }"#,
    )?;

    let original = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.envInput",
        |options| {
            options.set_env_var(env_name.to_vec(), original_env.to_vec());
            Ok(())
        },
    )?;
    assert_drv_aterm_contains_all(
        "original getEnv closure",
        &original.uncached,
        &[
            ("original derivation name", b"get-env-env-payload"),
            ("original getEnv arg", b"arg-env-payload"),
        ],
    );
    let original_force_canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    let original_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &original_trace,
        "original getEnv native closure",
    )?;

    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let options_for = |env_value: &[u8], parse_root: Option<&Path>, persist: bool| -> Result<_> {
        let mut options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
        options.set_env_var(env_name.to_vec(), env_value.to_vec());
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
        options.set_eval_cache_enabled(persist);
        Ok(options)
    };

    let (changed_uncached, changed_uncached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, options_for(changed_env, None, false)?)?,
        &file,
        "pkgs.envInput",
    )?;
    assert_eq!(changed_uncached_stats.force_cache_hits(), 0);
    assert_eq!(changed_uncached_stats.force_cache_misses(), 0);
    assert_ne!(
        changed_uncached, original.uncached,
        "changed getEnv value must change the uncached .drv closure"
    );
    assert_drv_aterm_contains_all(
        "changed uncached getEnv closure",
        &changed_uncached,
        &[
            ("changed derivation name", b"get-env-changed-payload"),
            ("changed getEnv arg", b"arg-changed-payload"),
        ],
    );
    assert_drv_aterm_lacks_all(
        "changed uncached getEnv closure",
        &changed_uncached,
        &[
            ("original derivation name", b"get-env-env-payload"),
            ("original getEnv arg", b"arg-env-payload"),
        ],
    );

    let (changed_cached, changed_cached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(changed_env, Some(&root.join("changed-get-env-parse")), true)?,
        )?,
        &file,
        "pkgs.envInput",
    )?;
    assert_eq!(
        changed_cached, changed_uncached,
        "stale persistent getEnv input should recompute to the changed closure"
    );
    assert_ne!(
        changed_cached, original.uncached,
        "stale persistent getEnv input must not replay the original closure"
    );
    assert!(
        changed_cached_stats.force_cache_misses() > 0,
        "stale persistent getEnv input should miss before recomputing"
    );
    let changed_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &changed_trace,
        "changed getEnv native closure",
    )?;
    assert_eq!(
        changed_trace_entry.0, original_trace_entry.0,
        "changed getEnv recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        changed_trace_entry.1, original_trace_entry.1,
        "changed getEnv recomputation should materialize a changed force-cache value"
    );

    let (changed_hit, changed_hit_stats, changed_hit_keys) =
        instantiate_file_closure_with_stats_and_hits(
            &NixNative::with_options(
                0,
                options_for(
                    changed_env,
                    Some(&root.join("changed-get-env-hit-parse")),
                    true,
                )?,
            )?,
            &file,
            "pkgs.envInput",
        )?;
    assert_eq!(
        changed_hit, changed_uncached,
        "post-recompute getEnv run should preserve the changed closure"
    );
    assert!(
        changed_hit_stats.force_cache_hits() > 0,
        "post-recompute getEnv run should replay the changed payload"
    );
    assert!(
        changed_hit_keys.contains(&changed_trace_entry.0),
        "post-recompute getEnv run should load the changed force-cache metadata key"
    );

    let mut canaries = original_force_canaries;
    canaries.extend(persistent_force_cache_surface_canaries(&persist_root)?);
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "getEnv root file",
        &file,
    )?);
    canaries.extend(impure_trace_surface_canaries(
        "original getEnv trace",
        &original_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "changed getEnv trace",
        &changed_trace,
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "original getEnv closure",
        &original.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed uncached getEnv closure",
        &changed_uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed cached getEnv closure",
        &changed_cached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "post-recompute getEnv closure",
        &changed_hit,
        &canaries,
    );

    Ok(())
}

#[test]
fn native_file_cache_parity_harness_covers_current_time_configured_input() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-current-time");
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
          timestamp = b.toString b.currentTime;
        in {
          pkgs.currentTimeInput = derivationStrict {
            name = "current-time-${timestamp}";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [
              timestamp
            ];
          };
        }"#,
    )?;

    let original_time = 1_700_000_000;
    let changed_time = 1_700_000_123;
    let original = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.currentTimeInput",
        |options| options.set_current_time(original_time).map_err(Into::into),
    )?;
    assert_drv_aterm_contains_all(
        "original currentTime closure",
        &original.uncached,
        &[
            ("original derivation name", b"current-time-1700000000"),
            ("original timestamp arg", b"1700000000"),
        ],
    );
    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let options_for = |current_time: i64, parse_root: Option<&Path>, persist: bool| -> Result<_> {
        let mut options = TreeWalkOptions::with_current_time(current_time)?;
        options.set_store_dir(store_bytes.clone())?;
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
        options.set_eval_cache_enabled(persist);
        Ok(options)
    };

    let (changed_uncached, changed_uncached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, options_for(changed_time, None, false)?)?,
        &file,
        "pkgs.currentTimeInput",
    )?;
    assert_eq!(changed_uncached_stats.force_cache_hits(), 0);
    assert_eq!(changed_uncached_stats.force_cache_misses(), 0);
    assert_ne!(
        changed_uncached, original.uncached,
        "changed currentTime must change the uncached .drv closure"
    );
    assert_drv_aterm_contains_all(
        "changed uncached currentTime closure",
        &changed_uncached,
        &[
            ("changed derivation name", b"current-time-1700000123"),
            ("changed timestamp arg", b"1700000123"),
        ],
    );
    assert_drv_aterm_lacks_all(
        "changed uncached currentTime closure",
        &changed_uncached,
        &[
            ("original derivation name", b"current-time-1700000000"),
            ("original timestamp arg", b"1700000000"),
        ],
    );

    let (changed_cached, _changed_cached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(
                changed_time,
                Some(&root.join("changed-current-time-parse")),
                true,
            )?,
        )?,
        &file,
        "pkgs.currentTimeInput",
    )?;
    assert_eq!(
        changed_cached, changed_uncached,
        "currentTime should recompute to the changed uncached closure"
    );
    assert_ne!(
        changed_cached, original.uncached,
        "currentTime must not replay a stale original closure"
    );

    let mut canaries = persistent_force_cache_surface_canaries(&persist_root)?;
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "currentTime root file",
        &file,
    )?);
    canaries.extend(hot_xxh3_surface_canaries(
        "original currentTime hot xxh3",
        context_free_nix_string_xxh3(b"1700000000"),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "changed currentTime hot xxh3",
        context_free_nix_string_xxh3(b"1700000123"),
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "original currentTime closure",
        &original.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed uncached currentTime closure",
        &changed_uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed cached currentTime closure",
        &changed_cached,
        &canaries,
    );

    Ok(())
}
