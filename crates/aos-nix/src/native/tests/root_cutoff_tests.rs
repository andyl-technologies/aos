//! Integration tests for root-level early cutoff over the native evaluator.

use super::*;
use crate::cache::PersistRootRecordKey;

fn cutoff_options(
    store: &Path,
    persist: &Path,
    cutoff: bool,
    check: bool,
) -> Result<TreeWalkOptions> {
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_persist_cache_root(persist);
    options.set_eval_cache_enabled(true);
    options.set_root_cutoff_enabled(cutoff);
    options.set_root_cutoff_check(check);
    Ok(options)
}

/// Reconstructs the durable root-record key the hook would compute for `file`.
fn record_key(native: &NixNative, file: &Path, attr: &str) -> Result<PersistRootRecordKey> {
    let mut options = native.file_instantiation_options();
    let file = native_source_file(file, &options)?;
    let source = fs::read(&file)?;
    let base = file.parent().unwrap_or_else(|| Path::new("/"));
    options.set_path_literal_base(path_bytes(base)?)?;
    Ok(crate::native::root_cutoff::root_record_key(
        &file, &source, attr, &options,
    ))
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

struct Fixture {
    _cleanup: TempTreeCleanup,
    store: PathBuf,
    persist: PathBuf,
    dir: PathBuf,
    file: PathBuf,
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
        persist: root.join("persist"),
        file: dir.join("default.nix"),
        dir,
        _cleanup: cleanup,
    })
}

#[test]
fn warm_run_answers_from_the_root_record() -> Result<()> {
    let fx = fixture("aos-nix-root-cutoff-hit")?;
    write_derivation(&fx.file, r#""cutoff-hit""#)?;
    let options = cutoff_options(&fx.store, &fx.persist, true, false)?;

    let cold = NixNative::with_options(0, options.clone())?;
    let (cold_closure, cold_stats) = cold.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(
        cold_stats.root_cutoffs(),
        0,
        "the cold run evaluates normally"
    );

    let warm = NixNative::with_options(0, options)?;
    let (warm_closure, warm_stats) = warm.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(
        warm_stats.root_cutoffs(),
        1,
        "the warm run is served by a root cutoff"
    );
    assert_eq!(warm_stats.thunks_forced(), 0, "a cutoff forces no thunks");
    assert_eq!(
        warm_closure, cold_closure,
        "the cutoff closure equals the evaluated closure"
    );
    Ok(())
}

#[test]
fn changed_input_file_misses_and_falls_through() -> Result<()> {
    let fx = fixture("aos-nix-root-cutoff-changed-input")?;
    let dep = fx.dir.join("dep.txt");
    fs::write(&dep, "vone")?;
    write_derivation(&fx.file, r#""cutoff-${builtins.readFile ./dep.txt}""#)?;
    let options = cutoff_options(&fx.store, &fx.persist, true, false)?;

    let cold = NixNative::with_options(0, options.clone())?;
    let (cold_closure, _) = cold.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // The entry file is byte-identical, so the record key is unchanged, but a
    // changed transitive input must fail trace revalidation and fall through.
    fs::write(&dep, "vtwo")?;
    let warm = NixNative::with_options(0, options)?;
    let (warm_closure, warm_stats) = warm.instantiate_closure_with_stats(&fx.file, "pkg")?;

    assert_eq!(
        warm_stats.root_cutoffs(),
        0,
        "a changed transitive input must not take the cutoff"
    );
    assert_ne!(
        warm_closure, cold_closure,
        "the re-evaluated closure reflects the changed input"
    );
    Ok(())
}

#[test]
fn incomplete_trace_writes_no_record() -> Result<()> {
    let fx = fixture("aos-nix-root-cutoff-incomplete")?;
    write_derivation(&fx.file, r#""cutoff-${toString builtins.currentTime}""#)?;
    let mut options = cutoff_options(&fx.store, &fx.persist, true, false)?;
    // Configure a deterministic clock so `currentTime` evaluates (rather than
    // hitting the CLI fallback) and records its uncacheable observation, which
    // latches the impure-input trace incomplete.
    options.set_current_time(1_700_000_000)?;

    let native = NixNative::with_options(0, options)?;
    let (_closure, stats) = native.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(stats.root_cutoffs(), 0, "the first run evaluates normally");

    // `builtins.currentTime` latches the impure-input trace incomplete, so no
    // durable record may be written for this instantiation.
    let key = record_key(&native, &fx.file, "pkg")?;
    let cache = PersistCache::open(&fx.persist)?;
    assert!(
        cache.load_root_instantiation(key)?.is_none(),
        "an incomplete trace must not persist a root record"
    );
    Ok(())
}

#[test]
fn kill_switch_suppresses_a_warm_hit() -> Result<()> {
    let fx = fixture("aos-nix-root-cutoff-killswitch")?;
    write_derivation(&fx.file, r#""cutoff-killswitch""#)?;

    let enabled = cutoff_options(&fx.store, &fx.persist, true, false)?;
    let cold = NixNative::with_options(0, enabled)?;
    cold.instantiate_closure_with_stats(&fx.file, "pkg")?;

    // With the kill switch engaged the record exists but must not be consulted.
    let disabled = cutoff_options(&fx.store, &fx.persist, false, false)?;
    let warm = NixNative::with_options(0, disabled)?;
    let (_closure, warm_stats) = warm.instantiate_closure_with_stats(&fx.file, "pkg")?;
    assert_eq!(
        warm_stats.root_cutoffs(),
        0,
        "AOS_NIX_ROOT_CUTOFF=0 must suppress the cutoff"
    );
    Ok(())
}

#[test]
fn check_mode_detects_a_corrupted_record() -> Result<()> {
    let fx = fixture("aos-nix-root-cutoff-check")?;
    write_derivation(&fx.file, r#""cutoff-check""#)?;
    let options = cutoff_options(&fx.store, &fx.persist, true, false)?;

    let native = NixNative::with_options(0, options)?;
    let (closure, _) = native.instantiate_closure_with_stats(&fx.file, "pkg")?;
    let key = record_key(&native, &fx.file, "pkg")?;

    // Overwrite the record under the same key with a corrupted closure whose
    // root `.drv` bytes no longer match a real evaluation. Newest-wins means the
    // cutoff will reconstruct these bad bytes.
    let (root, mut drvs) = closure.clone().into_parts();
    if let Some(bytes) = drvs.get_mut(&root) {
        bytes.extend_from_slice(b"corruption");
    }
    let cache = PersistCache::open(&fx.persist)?;
    cache.store_root_instantiation(key, root.as_os_str().as_bytes(), &drvs, &[], 0)?;

    // Check mode takes the cutoff, re-evaluates, and must report the divergence.
    let checked = cutoff_options(&fx.store, &fx.persist, true, true)?;
    let checker = NixNative::with_options(0, checked)?;
    let error = checker
        .instantiate_closure_with_stats(&fx.file, "pkg")
        .expect_err("check mode must reject a corrupted record");
    assert!(
        error.to_string().contains("diverged"),
        "unexpected error: {error}"
    );
    Ok(())
}
