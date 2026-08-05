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
fn native_file_cache_parity_harness_covers_absent_empty_and_pure_get_env() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-get-env-absent-pure");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let store = root.join("store");
    let persist_root = root.join("persist");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;

    let env_name = b"AOS_NATIVE_FILE_CACHE_OPTIONAL_ENV";
    let empty_env = b"".as_slice();
    let present_env = b"now-present".as_slice();
    let absent_trace = vec![ImpureInputFingerprint::get_env(env_name, None)?];
    let empty_trace = vec![ImpureInputFingerprint::get_env(env_name, Some(empty_env))?];
    let present_trace = vec![ImpureInputFingerprint::get_env(
        env_name,
        Some(present_env),
    )?];
    let absent_input = absent_trace[0]
        .as_cacheable()
        .expect("absent getEnv trace is cacheable");
    let empty_input = empty_trace[0]
        .as_cacheable()
        .expect("configured empty getEnv trace is cacheable");
    assert_eq!(
        absent_input.identity(),
        empty_input.identity(),
        "absent and configured empty getEnv should probe the same environment variable"
    );
    assert_ne!(
        absent_input.observation_hash(),
        empty_input.observation_hash(),
        "absent and configured empty getEnv must stay distinct cache observations"
    );
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          b = builtins;
          payload = b.getEnv "AOS_NATIVE_FILE_CACHE_OPTIONAL_ENV";
          marker = if payload == "" then "empty" else payload;
        in {
          pkgs.optionalEnvInput = derivationStrict {
            name = "get-env-${marker}";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [
              marker
              "arg-${marker}"
            ];
          };
        }"#,
    )?;

    let original = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.optionalEnvInput",
        |_| Ok(()),
    )?;
    assert_drv_aterm_contains_all(
        "absent getEnv closure",
        &original.uncached,
        &[
            ("absent derivation name", b"get-env-empty"),
            ("absent getEnv arg", b"arg-empty"),
        ],
    );
    let original_force_canaries = assert_persistent_force_cache_payload_entries(&persist_root)?;
    let absent_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &absent_trace,
        "absent getEnv native closure",
    )?;

    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let options_for =
        |mode, env_value: Option<&[u8]>, parse_root: Option<&Path>, persist| -> Result<_> {
            let mut options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
            options.set_eval_mode(mode);
            if mode == EvalMode::Pure {
                options.add_allowed_path(root.as_os_str().as_bytes().to_vec())?;
            }
            if let Some(env_value) = env_value {
                options.set_env_var(env_name.to_vec(), env_value.to_vec());
            } else {
                options.clear_env_var(env_name);
            }
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

    let (empty_uncached, empty_uncached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(EvalMode::Impure, Some(empty_env), None, false)?,
        )?,
        &file,
        "pkgs.optionalEnvInput",
    )?;
    assert_eq!(empty_uncached_stats.force_cache_hits(), 0);
    assert_eq!(empty_uncached_stats.force_cache_misses(), 0);
    assert_eq!(
        empty_uncached, original.uncached,
        "configured empty getEnv should match the absent empty-string closure"
    );

    let (empty_cached, empty_cached_stats, empty_cached_hit_keys) =
        instantiate_file_closure_with_stats_and_hits(
            &NixNative::with_options(
                0,
                options_for(
                    EvalMode::Impure,
                    Some(empty_env),
                    Some(&root.join("empty-get-env-parse")),
                    true,
                )?,
            )?,
            &file,
            "pkgs.optionalEnvInput",
        )?;
    assert_eq!(
        empty_cached, empty_uncached,
        "configured empty getEnv cached run should preserve the empty-string closure"
    );
    assert!(
        empty_cached_stats.force_cache_misses() > 0,
        "configured empty getEnv should miss stale absent input before recomputing"
    );
    assert!(
        !empty_cached_hit_keys.contains(&absent_trace_entry.0),
        "configured empty getEnv must not accept the stale absent force-cache metadata key as a hit"
    );
    let empty_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &empty_trace,
        "configured empty getEnv native closure",
    )?;
    assert_eq!(
        empty_trace_entry.0, absent_trace_entry.0,
        "configured empty getEnv recomputation should replace the same force-cache metadata key"
    );

    let (present_uncached, present_uncached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(EvalMode::Impure, Some(present_env), None, false)?,
        )?,
        &file,
        "pkgs.optionalEnvInput",
    )?;
    assert_eq!(present_uncached_stats.force_cache_hits(), 0);
    assert_eq!(present_uncached_stats.force_cache_misses(), 0);
    assert_ne!(
        present_uncached, original.uncached,
        "present getEnv value must change the uncached .drv closure"
    );
    assert_drv_aterm_contains_all(
        "present getEnv closure",
        &present_uncached,
        &[
            ("present derivation name", b"get-env-now-present"),
            ("present getEnv arg", b"arg-now-present"),
        ],
    );
    assert_drv_aterm_lacks_all(
        "present getEnv closure",
        &present_uncached,
        &[
            ("absent derivation name", b"get-env-empty"),
            ("absent getEnv arg", b"arg-empty"),
        ],
    );

    let (present_cached, present_cached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(
                EvalMode::Impure,
                Some(present_env),
                Some(&root.join("present-get-env-parse")),
                true,
            )?,
        )?,
        &file,
        "pkgs.optionalEnvInput",
    )?;
    assert_eq!(
        present_cached, present_uncached,
        "stale absent getEnv input should recompute to the present closure"
    );
    assert_ne!(
        present_cached, original.uncached,
        "stale absent getEnv input must not replay the empty-string closure"
    );
    assert!(
        present_cached_stats.force_cache_misses() > 0,
        "stale absent getEnv input should miss before recomputing"
    );
    let present_trace_entry = assert_persistent_force_cache_trace_log_contains(
        &persist_root,
        &present_trace,
        "present getEnv native closure",
    )?;
    assert_eq!(
        present_trace_entry.0, absent_trace_entry.0,
        "present getEnv recomputation should replace the same force-cache metadata key"
    );
    assert_ne!(
        present_trace_entry.1, absent_trace_entry.1,
        "present getEnv recomputation should materialize a changed force-cache value"
    );

    let (pure_uncached, pure_uncached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(EvalMode::Pure, Some(present_env), None, false)?,
        )?,
        &file,
        "pkgs.optionalEnvInput",
    )?;
    assert_eq!(pure_uncached_stats.force_cache_hits(), 0);
    assert_eq!(pure_uncached_stats.force_cache_misses(), 0);
    assert_eq!(
        pure_uncached, original.uncached,
        "pure mode should hide configured getEnv values and keep the empty-string closure"
    );
    assert_ne!(
        pure_uncached, present_uncached,
        "pure mode must not expose the configured present getEnv payload"
    );

    let (pure_cached, _pure_cached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(
                EvalMode::Pure,
                Some(present_env),
                Some(&root.join("pure-get-env-parse")),
                true,
            )?,
        )?,
        &file,
        "pkgs.optionalEnvInput",
    )?;
    assert_eq!(
        pure_cached, pure_uncached,
        "pure-mode cached run should preserve the empty-string getEnv closure"
    );
    assert_ne!(
        pure_cached, present_uncached,
        "pure-mode cached run must not replay the impure present getEnv payload"
    );

    let mut canaries = original_force_canaries;
    canaries.extend(persistent_force_cache_surface_canaries(&persist_root)?);
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "optional getEnv root file",
        &file,
    )?);
    canaries.extend(impure_trace_surface_canaries(
        "absent getEnv trace",
        &absent_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "configured empty getEnv trace",
        &empty_trace,
    ));
    canaries.extend(impure_trace_surface_canaries(
        "present getEnv trace",
        &present_trace,
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "absent getEnv closure",
        &original.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "configured empty uncached getEnv closure",
        &empty_uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "configured empty cached getEnv closure",
        &empty_cached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "present uncached getEnv closure",
        &present_uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "present cached getEnv closure",
        &present_cached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "pure uncached getEnv closure",
        &pure_uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "pure cached getEnv closure",
        &pure_cached,
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
