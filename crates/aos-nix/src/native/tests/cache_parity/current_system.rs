//! Ambient `currentSystem` option-salt closure parity canaries.

use super::*;

#[test]
fn native_file_cache_parity_harness_covers_current_system_option_salt() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-cache-parity-current-system");
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
          system = b.currentSystem;
        in {
          pkgs.currentSystem = derivationStrict {
            name = "current-system-${system}";
            inherit system;
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            args = [
              system
              "arg-${system}"
            ];
          };
        }"#,
    )?;

    let original_system = b"x86_64-linux".as_slice();
    let changed_system = b"aarch64-linux".as_slice();
    let original = native_file_closure_cache_parity(
        &root,
        &store,
        &persist_root,
        &file,
        "pkgs.currentSystem",
        |options| {
            options
                .set_current_system(original_system.to_vec())
                .map_err(Into::into)
        },
    )?;
    assert_drv_aterm_contains_all(
        "original currentSystem closure",
        &original.uncached,
        &[
            ("original derivation name", b"current-system-x86_64-linux"),
            ("original system field", b"x86_64-linux"),
            ("original arg", b"arg-x86_64-linux"),
        ],
    );
    let original_value_hash =
        CachedExpressionValue::context_free_string(original_system.to_vec()).value_hash()?;
    let changed_value_hash =
        CachedExpressionValue::context_free_string(changed_system.to_vec()).value_hash()?;
    let original_current_system_keys = persistent_force_cache_keys_for_value_hash(
        &persist_root,
        original_value_hash,
        "original currentSystem",
    )?;
    assert!(
        !original_current_system_keys.is_empty(),
        "original currentSystem run should materialize a force-cache payload"
    );

    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let options_for =
        |current_system: &[u8], parse_root: Option<&Path>, persist: bool| -> Result<_> {
            let mut options = TreeWalkOptions::with_current_system(current_system.to_vec())?;
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
        &NixNative::with_options(0, options_for(changed_system, None, false)?)?,
        &file,
        "pkgs.currentSystem",
    )?;
    assert_eq!(changed_uncached_stats.force_cache_hits(), 0);
    assert_eq!(changed_uncached_stats.force_cache_misses(), 0);
    assert_ne!(
        changed_uncached, original.uncached,
        "changed currentSystem option must change the uncached .drv closure"
    );
    assert_drv_aterm_contains_all(
        "changed uncached currentSystem closure",
        &changed_uncached,
        &[
            ("changed derivation name", b"current-system-aarch64-linux"),
            ("changed system field", b"aarch64-linux"),
            ("changed arg", b"arg-aarch64-linux"),
        ],
    );
    assert_drv_aterm_lacks_all(
        "changed uncached currentSystem closure",
        &changed_uncached,
        &[
            ("original derivation name", b"current-system-x86_64-linux"),
            ("original system field", b"x86_64-linux"),
            ("original arg", b"arg-x86_64-linux"),
        ],
    );

    let (changed_cached, changed_cached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(
                changed_system,
                Some(&root.join("changed-current-system-first-parse")),
                true,
            )?,
        )?,
        &file,
        "pkgs.currentSystem",
    )?;
    assert_eq!(
        changed_cached, changed_uncached,
        "currentSystem option-salted cache run should match the changed uncached closure"
    );
    assert_ne!(
        changed_cached, original.uncached,
        "currentSystem option-salted cache run must not replay the original closure"
    );
    assert_eq!(
        changed_cached_stats.force_cache_hits(),
        0,
        "changed currentSystem must not hit the original force-cache payload"
    );
    assert!(
        changed_cached_stats.force_cache_misses() > 0,
        "changed currentSystem should miss before materializing its own payload"
    );

    let (changed_materialized, changed_materialized_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(
            0,
            options_for(
                changed_system,
                Some(&root.join("changed-current-system-materialized-parse")),
                true,
            )?,
        )?,
        &file,
        "pkgs.currentSystem",
    )?;
    assert_eq!(
        changed_materialized, changed_uncached,
        "materializing changed currentSystem run should preserve the changed closure"
    );
    assert_eq!(
        changed_materialized_stats.force_cache_hits(),
        0,
        "materializing changed currentSystem run should not replay the original payload"
    );
    assert!(
        changed_materialized_stats.force_cache_misses() > 0,
        "materializing changed currentSystem run should miss before writing its payload"
    );
    let changed_current_system_keys = persistent_force_cache_keys_for_value_hash(
        &persist_root,
        changed_value_hash,
        "changed currentSystem",
    )?;
    assert!(
        !changed_current_system_keys.is_empty(),
        "changed currentSystem run should materialize a distinct force-cache payload"
    );
    for key in &changed_current_system_keys {
        assert!(
            !original_current_system_keys.contains(key),
            "changed currentSystem should use a distinct force-cache metadata key"
        );
    }

    let (changed_hit, changed_hit_stats, changed_hit_keys) =
        instantiate_file_closure_with_stats_and_hits(
            &NixNative::with_options(
                0,
                options_for(
                    changed_system,
                    Some(&root.join("changed-current-system-hit-parse")),
                    true,
                )?,
            )?,
            &file,
            "pkgs.currentSystem",
        )?;
    assert_eq!(
        changed_hit, changed_uncached,
        "fresh cached currentSystem run should preserve the changed closure"
    );
    assert!(
        changed_hit_stats.force_cache_hits() > 0,
        "fresh cached currentSystem run should replay the changed payload"
    );
    for key in &changed_current_system_keys {
        assert!(
            changed_hit_keys.contains(key),
            "fresh cached currentSystem run should load the changed currentSystem value-hash metadata key"
        );
    }
    for key in &original_current_system_keys {
        assert!(
            !changed_hit_keys.contains(key),
            "fresh cached currentSystem run should not load the original currentSystem value-hash metadata key"
        );
    }

    let mut canaries = persistent_force_cache_surface_canaries(&persist_root)?;
    canaries.extend(file_parse_artifact_surface_canaries(
        &root,
        "currentSystem root file",
        &file,
    )?);
    canaries.extend(hot_xxh3_surface_canaries(
        "original currentSystem hot xxh3",
        context_free_nix_string_xxh3(original_system),
    ));
    canaries.extend(hot_xxh3_surface_canaries(
        "changed currentSystem hot xxh3",
        context_free_nix_string_xxh3(changed_system),
    ));
    assert_native_closure_surfaces_do_not_contain_canaries(
        "original currentSystem closure",
        &original.uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed uncached currentSystem closure",
        &changed_uncached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed cached currentSystem closure",
        &changed_cached,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "changed materialized currentSystem closure",
        &changed_materialized,
        &canaries,
    );
    assert_native_closure_surfaces_do_not_contain_canaries(
        "fresh cached currentSystem closure",
        &changed_hit,
        &canaries,
    );

    Ok(())
}

fn persistent_force_cache_keys_for_value_hash(
    persist_root: &Path,
    value_hash: ValueHash,
    context: &str,
) -> Result<Vec<PersistNodeMetadataKey>> {
    let entries = PersistCache::open(persist_root)?
        .node_metadata_index()
        .latest_entries()?
        .into_iter()
        .filter_map(|entry| {
            (entry.value().materialized_value_hash() == Some(value_hash)).then_some(entry.key())
        })
        .collect::<Vec<_>>();
    assert!(
        !entries.is_empty(),
        "{context} should have at least one force-cache metadata entry for its materialized value"
    );
    Ok(entries)
}
