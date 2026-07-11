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
