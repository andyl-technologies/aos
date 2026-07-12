//! Integration tests for the MEMO-2 durable tiers: multi-location L2 disk
//! probing/promotion and the L3 network record tier.

use super::*;
use crate::cache::{PersistDiskLocation, PersistLatencyClass};
use crate::eval::{MemoNetMode, MemoNetOptions, MemoOptions};
use crate::native::tests::test_memo_server::MemoTestServer;

struct Fixture {
    _cleanup: TempTreeCleanup,
    root: PathBuf,
    store: PathBuf,
    file: PathBuf,
    dir: PathBuf,
}

fn fixture(prefix: &str) -> Result<Fixture> {
    let root = unique_temp_dir(prefix);
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let cleanup = TempTreeCleanup::new(root.clone());
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    Ok(Fixture {
        store: root.join("store"),
        file: dir.join("default.nix"),
        dir,
        root,
        _cleanup: cleanup,
    })
}

fn write_derivation(file: &Path, name_expr: &str) -> Result<()> {
    fs::write(
        file,
        format!(
            r#"{{ pkg = derivationStrict {{
  name = {name_expr};
  system = "x86_64-linux";
  builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
}}; }}"#
        ),
    )?;
    Ok(())
}

/// Builds cutoff-enabled options with `persist` as the primary location.
fn tier_options(fx: &Fixture, persist: &Path) -> Result<TreeWalkOptions> {
    let mut options = TreeWalkOptions::with_store_dir(fx.store.as_os_str().as_bytes().to_vec())?;
    options.set_persist_cache_root(persist);
    options.set_eval_cache_enabled(true);
    options.set_root_cutoff_enabled(true);
    Ok(options)
}

fn secondary(fx: &Fixture, name: &str) -> PersistDiskLocation {
    PersistDiskLocation::new(PersistLatencyClass::Hdd, fx.root.join(name))
}

#[test]
fn secondary_location_hit_promotes_to_the_primary() -> Result<()> {
    let fx = fixture("aos-nix-memo-l2-promote")?;
    write_derivation(&fx.file, r#""memo-l2-promote""#)?;

    // Cold run records into location A.
    let location_a = fx.root.join("persist-a");
    let cold = NixNative::with_options(0, tier_options(&fx, &location_a)?)?;
    let (cold_closure, cold_stats) = cold.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(cold_stats.root_cutoffs(), 0);

    // Warm run with a fresh primary B and A demoted to a secondary: the hit
    // must come from the secondary and be promoted into B.
    let location_b = fx.root.join("persist-b");
    let mut options = tier_options(&fx, &location_b)?;
    options.set_memo_disk_locations(vec![PersistDiskLocation::new(
        PersistLatencyClass::Hdd,
        &location_a,
    )]);
    let warm = NixNative::with_options(0, options)?;
    let (warm_closure, warm_stats) = warm.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(warm_stats.root_cutoffs(), 1, "the secondary answers");
    assert_eq!(warm_stats.memo_l2_secondary_hits(), 1);
    assert_eq!(warm_stats.memo_l2_promotions(), 1);
    assert_eq!(warm_closure, cold_closure);

    // A third run against B alone must answer from the promoted record.
    let promoted = NixNative::with_options(0, tier_options(&fx, &location_b)?)?;
    let (promoted_closure, promoted_stats) =
        promoted.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(
        promoted_stats.root_cutoffs(),
        1,
        "the promotion installed the record into the primary"
    );
    assert_eq!(
        promoted_stats.memo_l2_secondary_hits(),
        0,
        "no secondary is configured on the third run"
    );
    assert_eq!(promoted_closure, cold_closure);
    Ok(())
}

#[test]
fn primary_hit_takes_precedence_over_secondaries() -> Result<()> {
    let fx = fixture("aos-nix-memo-l2-order")?;
    write_derivation(&fx.file, r#""memo-l2-order""#)?;

    let primary = fx.root.join("persist-primary");
    let cold = NixNative::with_options(0, tier_options(&fx, &primary)?)?;
    cold.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // The record exists in the primary; a configured secondary must not be
    // consulted (its counters stay zero even though it also holds nothing).
    let mut options = tier_options(&fx, &primary)?;
    options.set_memo_disk_locations(vec![secondary(&fx, "persist-cold")]);
    let warm = NixNative::with_options(0, options)?;
    let (_, stats) = warm.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 1);
    assert_eq!(stats.memo_l2_secondary_hits(), 0);
    assert_eq!(stats.memo_l2_secondary_misses(), 0);
    Ok(())
}

#[test]
fn missing_secondary_location_is_a_miss_not_an_error() -> Result<()> {
    let fx = fixture("aos-nix-memo-l2-lost")?;
    write_derivation(&fx.file, r#""memo-l2-lost""#)?;

    // The secondary path does not exist; PersistCache::open would create it,
    // so point at a path whose parent is an unreadable *file* to force a real
    // open failure — the eval must still succeed by evaluating normally.
    let blocker = fx.root.join("blocker");
    fs::write(&blocker, b"not a directory")?;
    let mut options = tier_options(&fx, &fx.root.join("persist-primary"))?;
    options.set_memo_disk_locations(vec![PersistDiskLocation::new(
        PersistLatencyClass::Hdd,
        blocker.join("nested"),
    )]);
    let native = NixNative::with_options(0, options)?;
    let (_, stats) = native.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 0, "a cold run evaluates normally");
    Ok(())
}

#[test]
fn secondary_hit_revalidates_impure_inputs() -> Result<()> {
    let fx = fixture("aos-nix-memo-l2-reval")?;
    let dep = fx.dir.join("dep.txt");
    fs::write(&dep, "vone")?;
    write_derivation(&fx.file, r#""memo-l2-${builtins.readFile ./dep.txt}""#)?;

    let location_a = fx.root.join("persist-a");
    let cold = NixNative::with_options(0, tier_options(&fx, &location_a)?)?;
    let (cold_closure, _) = cold.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // The world changed; the secondary's record must fail revalidation and
    // fall through to a full evaluation — never replay stale bytes.
    fs::write(&dep, "vtwo")?;
    let mut options = tier_options(&fx, &fx.root.join("persist-b"))?;
    options.set_memo_disk_locations(vec![PersistDiskLocation::new(
        PersistLatencyClass::Hdd,
        &location_a,
    )]);
    let warm = NixNative::with_options(0, options)?;
    let (warm_closure, stats) = warm.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 0);
    assert_eq!(stats.memo_l2_reval_failures(), 1);
    assert_ne!(warm_closure, cold_closure);
    Ok(())
}

#[test]
fn check_l2_detects_a_corrupted_secondary_record() -> Result<()> {
    let fx = fixture("aos-nix-memo-l2-check")?;
    write_derivation(&fx.file, r#""memo-l2-check""#)?;

    let location_a = fx.root.join("persist-a");
    let cold = NixNative::with_options(0, tier_options(&fx, &location_a)?)?;
    let (closure, _) = cold.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // Corrupt the record in the secondary under the same key.
    let key = {
        let mut options = cold.file_instantiation_options();
        let file = native_source_file(&fx.file, &options)?;
        let source = fs::read(&file)?;
        let base = file.parent().unwrap_or_else(|| Path::new("/"));
        options.set_path_literal_base(path_bytes(base)?)?;
        crate::native::root_cutoff::root_record_key(&file, &source, "pkg", &options)
    };
    let (root, mut drvs) = closure.into_parts();
    if let Some(bytes) = drvs.get_mut(&root) {
        bytes.extend_from_slice(b"corruption");
    }
    let cache = PersistCache::open(&location_a)?;
    cache.store_root_instantiation(key, root.as_os_str().as_bytes(), &drvs, &[], 0)?;

    let mut options = tier_options(&fx, &fx.root.join("persist-b"))?;
    options.set_memo_disk_locations(vec![PersistDiskLocation::new(
        PersistLatencyClass::Hdd,
        &location_a,
    )]);
    options.set_memo_options(MemoOptions {
        check_l2: true,
        ..MemoOptions::default()
    });
    let checker = NixNative::with_options(0, options)?;
    let error = checker
        .instantiate_closure_with_stats(&fx.file, "pkg")
        .expect_err("check_l2 must reject a corrupted secondary record");
    assert!(
        error.to_string().contains("diverged"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn import_parse_artifacts_ride_secondary_locations() -> Result<()> {
    let fx = fixture("aos-nix-memo-l2-parse")?;
    fs::write(fx.dir.join("lib.nix"), "{ name = \"memo-l2-parse\"; }")?;
    fs::write(
        &fx.file,
        r#"{ pkg = derivationStrict {
  name = (import ./lib.nix).name;
  system = "x86_64-linux";
  builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
}; }"#,
    )?;

    // Cold run materializes the import's parse artifact into location A.
    let location_a = fx.root.join("persist-a");
    let mut cold_options = tier_options(&fx, &location_a)?;
    cold_options.set_parse_cache_root(fx.root.join("parse-a"));
    cold_options.set_root_cutoff_enabled(false);
    let cold = NixNative::with_options(0, cold_options)?;
    cold.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // Warm run with a fresh primary and parse dir: the import's artifact can
    // only come from the secondary, and must be promoted into the primary.
    let mut options = tier_options(&fx, &fx.root.join("persist-b"))?;
    options.set_parse_cache_root(fx.root.join("parse-b"));
    options.set_root_cutoff_enabled(false);
    options.set_memo_disk_locations(vec![PersistDiskLocation::new(
        PersistLatencyClass::Hdd,
        &location_a,
    )]);
    let warm = NixNative::with_options(0, options)?;
    let (_, stats) = warm.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert!(
        stats.memo_l2_secondary_hits() >= 1,
        "the import's parse artifact must hydrate from the secondary (stats: {stats:?})"
    );
    assert!(
        stats.memo_l2_promotions() >= 1,
        "the secondary parse artifact must be promoted into the primary"
    );
    Ok(())
}

fn net_options(endpoint: String, mode: MemoNetMode) -> MemoNetOptions {
    MemoNetOptions {
        endpoint,
        mode,
        timeout_ms: 2_000,
    }
}

fn net_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::native::memo_net::test_guard()
}

#[test]
fn network_round_trip_publishes_fetches_and_installs() -> Result<()> {
    let _net = net_lock();
    let fx = fixture("aos-nix-memo-net-roundtrip")?;
    write_derivation(&fx.file, r#""memo-net-roundtrip""#)?;
    let server = MemoTestServer::spawn()?;

    // A writable cold run publishes its record to the endpoint.
    let mut publisher_options = tier_options(&fx, &fx.root.join("persist-a"))?;
    publisher_options.set_memo_net(Some(net_options(
        server.endpoint(),
        MemoNetMode::ReadWrite,
    )));
    let publisher = NixNative::with_options(0, publisher_options)?;
    let (cold_closure, _) = publisher.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(server.record_count(), 1, "the cold run publishes one record");

    // A read-only run with a fresh primary fetches, validates, and installs.
    let location_b = fx.root.join("persist-b");
    let mut fetcher_options = tier_options(&fx, &location_b)?;
    fetcher_options.set_memo_net(Some(net_options(server.endpoint(), MemoNetMode::ReadOnly)));
    let fetcher = NixNative::with_options(0, fetcher_options)?;
    let (net_closure, net_stats) = fetcher.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(net_stats.root_cutoffs(), 1, "the network record answers");
    assert_eq!(net_stats.memo_net_hits(), 1);
    assert_eq!(net_closure, cold_closure);

    // The fetched record was installed locally: a later run with no network
    // configured answers from the primary.
    let local = NixNative::with_options(0, tier_options(&fx, &location_b)?)?;
    let (local_closure, local_stats) = local.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(local_stats.root_cutoffs(), 1);
    assert_eq!(local_stats.memo_net_hits(), 0);
    assert_eq!(local_closure, cold_closure);
    Ok(())
}

#[test]
fn poisoned_network_record_is_rejected() -> Result<()> {
    let _net = net_lock();
    let fx = fixture("aos-nix-memo-net-poison")?;
    write_derivation(&fx.file, r#""memo-net-poison""#)?;
    let server = MemoTestServer::spawn()?;

    let mut publisher_options = tier_options(&fx, &fx.root.join("persist-a"))?;
    publisher_options.set_memo_net(Some(net_options(
        server.endpoint(),
        MemoNetMode::ReadWrite,
    )));
    let publisher = NixNative::with_options(0, publisher_options)?;
    let (cold_closure, _) = publisher.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // Corrupt one byte of the stored bundle: the fetch must fail content
    // validation, count an error, and fall through to a correct evaluation.
    server.mutate_records(|records| {
        for bytes in records.values_mut() {
            if let Some(last) = bytes.last_mut() {
                *last ^= 0xff;
            }
        }
    });
    let mut fetcher_options = tier_options(&fx, &fx.root.join("persist-b"))?;
    fetcher_options.set_memo_net(Some(net_options(server.endpoint(), MemoNetMode::ReadOnly)));
    let fetcher = NixNative::with_options(0, fetcher_options)?;
    let (closure, stats) = fetcher.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 0, "the poisoned record must miss");
    assert_eq!(stats.memo_net_errors(), 1);
    assert_eq!(closure, cold_closure, "the fallback evaluation is correct");
    Ok(())
}

#[test]
fn offline_endpoint_degrades_to_a_miss() -> Result<()> {
    let _net = net_lock();
    let fx = fixture("aos-nix-memo-net-offline")?;
    write_derivation(&fx.file, r#""memo-net-offline""#)?;

    // Nothing listens on the endpoint; the eval must succeed regardless.
    let mut options = tier_options(&fx, &fx.root.join("persist-a"))?;
    options.set_memo_net(Some(net_options(
        "http://127.0.0.1:1".to_string(),
        MemoNetMode::ReadOnly,
    )));
    let native = NixNative::with_options(0, options)?;
    let (_, stats) = native.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 0);
    assert_eq!(stats.memo_net_errors(), 1);
    crate::native::memo_net::reset_backoff_for_tests();
    Ok(())
}

#[test]
fn network_record_revalidates_impure_inputs() -> Result<()> {
    let _net = net_lock();
    let fx = fixture("aos-nix-memo-net-reval")?;
    let dep = fx.dir.join("dep.txt");
    fs::write(&dep, "vone")?;
    write_derivation(&fx.file, r#""memo-net-${builtins.readFile ./dep.txt}""#)?;
    let server = MemoTestServer::spawn()?;

    let mut publisher_options = tier_options(&fx, &fx.root.join("persist-a"))?;
    publisher_options.set_memo_net(Some(net_options(
        server.endpoint(),
        MemoNetMode::ReadWrite,
    )));
    let publisher = NixNative::with_options(0, publisher_options)?;
    let (cold_closure, _) = publisher.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // The record on the endpoint observed dep=vone; with dep=vtwo its slice
    // must fail local revalidation and the run must evaluate fresh bytes.
    fs::write(&dep, "vtwo")?;
    let mut fetcher_options = tier_options(&fx, &fx.root.join("persist-b"))?;
    fetcher_options.set_memo_net(Some(net_options(server.endpoint(), MemoNetMode::ReadOnly)));
    let fetcher = NixNative::with_options(0, fetcher_options)?;
    let (closure, stats) = fetcher.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 0);
    assert_eq!(stats.memo_net_reval_failures(), 1);
    assert_ne!(closure, cold_closure);
    Ok(())
}

#[test]
fn check_l3_detects_a_swapped_network_record() -> Result<()> {
    let _net = net_lock();
    let fx = fixture("aos-nix-memo-net-check")?;
    fs::write(
        &fx.file,
        r#"{ pkg = derivationStrict {
  name = "memo-net-swap-a";
  system = "x86_64-linux";
  builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
};
pkg2 = derivationStrict {
  name = "memo-net-swap-b";
  system = "x86_64-linux";
  builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
}; }"#,
    )?;
    let server = MemoTestServer::spawn()?;

    // Publish both attrs, then swap their records on the endpoint: each stays
    // internally valid (hashes pass, slices revalidate) but answers the wrong
    // computation — the exact wrong-key poisoning CHECK exists to catch.
    let mut publisher_options = tier_options(&fx, &fx.root.join("persist-a"))?;
    publisher_options.set_memo_net(Some(net_options(
        server.endpoint(),
        MemoNetMode::ReadWrite,
    )));
    let publisher = NixNative::with_options(0, publisher_options)?;
    publisher.instantiate_closure_with_stats(&fx.file, "pkg")?;
    publisher.instantiate_closure_with_stats(&fx.file, "pkg2")?;
    assert_eq!(server.record_count(), 2);
    server.mutate_records(|records| {
        let keys: Vec<String> = records.keys().cloned().collect();
        if let [first, second] = keys.as_slice() {
            let bytes_first = records[first].clone();
            let bytes_second = records[second].clone();
            records.insert(first.clone(), bytes_second);
            records.insert(second.clone(), bytes_first);
        }
    });

    let mut fetcher_options = tier_options(&fx, &fx.root.join("persist-b"))?;
    fetcher_options.set_memo_net(Some(net_options(server.endpoint(), MemoNetMode::ReadOnly)));
    fetcher_options.set_memo_options(MemoOptions {
        check_l3: true,
        ..MemoOptions::default()
    });
    let fetcher = NixNative::with_options(0, fetcher_options)?;
    let error = fetcher
        .instantiate_closure_with_stats(&fx.file, "pkg")
        .expect_err("check_l3 must reject a swapped record");
    assert!(
        error.to_string().contains("diverged"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn reachable_endpoint_missing_record_is_a_clean_miss() -> Result<()> {
    let _net = net_lock();
    let fx = fixture("aos-nix-memo-net-404")?;
    write_derivation(&fx.file, r#""memo-net-404""#)?;
    // A reachable server that has never seen this record answers 404. That is a
    // clean miss (not an error, no backoff latch): a present-but-empty catalog
    // is a normal state, unlike a transport failure.
    let server = MemoTestServer::spawn()?;
    let mut options = tier_options(&fx, &fx.root.join("persist-a"))?;
    options.set_memo_net(Some(net_options(server.endpoint(), MemoNetMode::ReadOnly)));
    let native = NixNative::with_options(0, options)?;
    let (_, stats) = native.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 0, "a missing record evaluates normally");
    assert_eq!(stats.memo_net_misses(), 1, "404 is a miss");
    assert_eq!(stats.memo_net_errors(), 0, "404 is not an error");
    Ok(())
}

#[test]
fn server_error_status_is_an_advisory_miss() -> Result<()> {
    let _net = net_lock();
    let fx = fixture("aos-nix-memo-net-5xx")?;
    write_derivation(&fx.file, r#""memo-net-5xx""#)?;
    let server = MemoTestServer::spawn()?;

    let mut publisher_options = tier_options(&fx, &fx.root.join("persist-a"))?;
    publisher_options.set_memo_net(Some(net_options(
        server.endpoint(),
        MemoNetMode::ReadWrite,
    )));
    let publisher = NixNative::with_options(0, publisher_options)?;
    let (cold_closure, _) = publisher.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // The server now answers 500 for every request: the fetch is an advisory
    // error and the run evaluates correctly. A received non-success status is
    // not a transport failure, so it does not latch the process backoff.
    server.force_status(500);
    let mut fetcher_options = tier_options(&fx, &fx.root.join("persist-b"))?;
    fetcher_options.set_memo_net(Some(net_options(server.endpoint(), MemoNetMode::ReadOnly)));
    let fetcher = NixNative::with_options(0, fetcher_options)?;
    let (closure, stats) = fetcher.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 0, "a 5xx record must miss");
    assert_eq!(stats.memo_net_errors(), 1);
    assert_eq!(closure, cold_closure, "the fallback evaluation is correct");
    Ok(())
}

#[test]
fn truncated_network_bundle_is_rejected() -> Result<()> {
    let _net = net_lock();
    let fx = fixture("aos-nix-memo-net-truncated")?;
    write_derivation(&fx.file, r#""memo-net-truncated""#)?;
    let server = MemoTestServer::spawn()?;

    let mut publisher_options = tier_options(&fx, &fx.root.join("persist-a"))?;
    publisher_options.set_memo_net(Some(net_options(
        server.endpoint(),
        MemoNetMode::ReadWrite,
    )));
    let publisher = NixNative::with_options(0, publisher_options)?;
    let (cold_closure, _) = publisher.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // Truncate every stored bundle to a stub too short to decode: the codec
    // rejects it, the fetch is an advisory error, and the run evaluates fresh.
    server.mutate_records(|records| {
        for bytes in records.values_mut() {
            bytes.truncate(4);
        }
    });
    let mut fetcher_options = tier_options(&fx, &fx.root.join("persist-b"))?;
    fetcher_options.set_memo_net(Some(net_options(server.endpoint(), MemoNetMode::ReadOnly)));
    let fetcher = NixNative::with_options(0, fetcher_options)?;
    let (closure, stats) = fetcher.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 0, "a truncated record must miss");
    assert_eq!(stats.memo_net_errors(), 1);
    assert_eq!(closure, cold_closure, "the fallback evaluation is correct");
    Ok(())
}

#[test]
fn read_only_mode_never_publishes() -> Result<()> {
    let _net = net_lock();
    let fx = fixture("aos-nix-memo-net-ro-suppress")?;
    write_derivation(&fx.file, r#""memo-net-ro-suppress""#)?;
    let server = MemoTestServer::spawn()?;

    // A cold read-only run computes a fresh record but must NOT publish it: the
    // rw policy gate lives on the client, so a public/interactive evaluator
    // never writes to the catalog.
    let mut options = tier_options(&fx, &fx.root.join("persist-a"))?;
    options.set_memo_net(Some(net_options(server.endpoint(), MemoNetMode::ReadOnly)));
    let native = NixNative::with_options(0, options)?;
    native.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(
        server.record_count(),
        0,
        "a read-only evaluator must not publish records"
    );
    Ok(())
}
