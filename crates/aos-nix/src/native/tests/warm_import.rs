//! Durable force-cache replay tests for compute-heavy imported values.

use super::*;

fn cached_options(parse: &Path, persist: &Path) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(parse);
    options.set_persist_cache_root(persist);
    options.set_eval_cache_enabled(true);
    options
}

#[test]
fn persistent_import_hit_skips_the_imported_scalar_body() -> Result<()> {
    let root = unique_temp_dir("native-warm-import-scalar");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let source = root.join("leaf.nix");
    let entry = root.join("root.nix");
    let parse = root.join("parse");
    let persist = root.join("persist");
    fs::write(
        &source,
        r#"let
  values = builtins.genList (i: (i + 1) * (i + 3)) 2048;
in builtins.foldl' (sum: value: sum + value) 0 values
"#,
    )?;
    fs::write(&entry, "{ total = import ./leaf.nix; }\n")?;
    let expression = format!(
        "(import {}).total",
        nix_string_literal(&path_bytes(&entry)?)?
    );

    let evaluate = || {
        NixNative::with_options(0, cached_options(&parse, &persist))?
            .eval_expr_with_stats(&expression)
    };
    let (first_json, first_stats) = evaluate()?;
    let (materialized_json, materialized_stats) = evaluate()?;
    let (hit_json, hit_stats) = evaluate()?;

    assert_eq!(materialized_json, first_json);
    assert_eq!(hit_json, first_json);
    assert!(
        hit_stats.force_cache_hits() > 0,
        "the third fresh runtime should replay a durable force payload"
    );
    assert!(
        hit_stats.thunks_forced() <= 4,
        "a durable scalar import hit should skip work: first={}, materialized={}, hit={}",
        first_stats.thunks_forced(),
        materialized_stats.thunks_forced(),
        hit_stats.thunks_forced(),
    );
    assert!(
        hit_stats.early_cutoffs() > 0,
        "the settled run should report a local early cutoff"
    );

    fs::write(
        &source,
        r#"let
  values = builtins.genList (i: (i + 5) * (i + 7)) 2048;
in builtins.foldl' (sum: value: sum + value) 0 values
"#,
    )?;
    let (changed_json, changed_stats) = evaluate()?;
    let (changed_materialized_json, _) = evaluate()?;
    let (changed_hit_json, changed_hit_stats) = evaluate()?;
    assert_ne!(changed_json, first_json);
    assert_eq!(changed_materialized_json, changed_json);
    assert_eq!(changed_hit_json, changed_json);
    assert!(
        changed_stats.thunks_forced() > 2_000,
        "changed imported source must recompute its pure root"
    );
    assert!(
        changed_hit_stats.thunks_forced() <= 4 && changed_hit_stats.force_cache_hits() > 0,
        "the changed source should settle into its own warm root payload: changed={}, hit={}, cache_hits={}",
        changed_stats.thunks_forced(),
        changed_hit_stats.thunks_forced(),
        changed_hit_stats.force_cache_hits(),
    );
    Ok(())
}

#[test]
fn changed_sibling_import_reuses_unchanged_expensive_dependency_after_one_run() -> Result<()> {
    let root = unique_temp_dir("native-warm-import-sibling-edit");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let _cleanup = TempTreeCleanup::new(root.clone());
    let leaf = root.join("leaf.nix");
    let host = root.join("host.nix");
    let entry = root.join("entry.nix");
    let parse = root.join("parse");
    let persist = root.join("persist");
    fs::write(
        &leaf,
        r#"let
  values = builtins.genList (i: (i + 1) * (i + 3)) 2048;
in builtins.foldl' (sum: value: sum + value) 0 values
"#,
    )?;
    fs::write(
        &host,
        r#"{ label = "before"; offset = 1; }
"#,
    )?;
    fs::write(
        &entry,
        r#"let host = import ./host.nix;
in {
  label = host.label;
  total = (import ./leaf.nix) + host.offset;
}
"#,
    )?;
    let expression = format!("import {}", nix_string_literal(&path_bytes(&entry)?)?);
    let evaluate = || {
        NixNative::with_options(0, cached_options(&parse, &persist))?
            .eval_expr_with_stats(&expression)
    };

    let (initial_json, initial_stats) = evaluate()?;
    assert!(
        initial_stats.force_cache_materialization_materializes() > 0,
        "a profitable pure import should materialize on its first demand"
    );

    fs::write(
        &host,
        r#"{ label = "after"; offset = 2; }
"#,
    )?;
    let (warm_json, warm_stats) = evaluate()?;
    let cold_options = cached_options(&root.join("cold-parse"), &root.join("cold-persist"));
    let (cold_json, cold_stats) =
        NixNative::with_options(0, cold_options)?.eval_expr_with_stats(&expression)?;

    assert_ne!(
        warm_json, initial_json,
        "the edited host import must take effect"
    );
    assert_eq!(
        warm_json, cold_json,
        "incremental and cold results must match"
    );
    assert!(
        warm_stats.force_cache_hits() > 0 && warm_stats.early_cutoffs() > 0,
        "the unchanged dependency should produce cache-hit and cutoff telemetry: hits={}, cutoffs={}",
        warm_stats.force_cache_hits(),
        warm_stats.early_cutoffs(),
    );
    assert!(
        warm_stats.thunks_forced().saturating_mul(5) <= cold_stats.thunks_forced(),
        "edited-host warm work must not exceed 20% of fresh cold work: warm={}, cold={}",
        warm_stats.thunks_forced(),
        cold_stats.thunks_forced(),
    );
    Ok(())
}
