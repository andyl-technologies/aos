//! Cross-module call-summary runtime tests.

use super::*;
use std::os::unix::ffi::OsStrExt;

fn imported_eval(
    imported: &[u8],
    expression: impl FnOnce(&Path) -> String,
) -> (TreeWalk, Result<Value, TreeWalkError>) {
    let root = fs::canonicalize(unique_temp_dir("cross-module-call-summary"))
        .expect("temp directory canonicalizes");
    let imported_path = root.join("function.nix");
    fs::write(&imported_path, imported).expect("import source writes");
    let source = expression(&imported_path);
    let mut ir = lower(&source);
    crate::compile::annotate_ir(&mut ir).expect("caller analysis succeeds");
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let result = evaluator.eval_root();
    (evaluator, result)
}

#[test]
fn imported_formal_demand_elides_argument_and_binding_thunks() {
    let (evaluator, result) = imported_eval(b"{ x, ... }: builtins.seq x 1", |path| {
        format!(
            "builtins.deepSeq ((import {}) {{ x = [ 1 ]; }}) 1",
            path.display()
        )
    });
    result.expect("cross-module call evaluates");

    assert!(evaluator.stats_snapshot().thunks_elided() >= 2);
    assert!(evaluator.stats_snapshot().binding_assembly_elisions() >= 1);
}

#[test]
fn imported_summary_does_not_cross_pattern_errors() {
    let (evaluator, result) = imported_eval(b"{ x }: builtins.seq x 1", |path| {
        format!(
            "builtins.tryEval ((import {}) {{ x = builtins.trace \"wrong\" 1; extra = 2; }})",
            path.display()
        )
    });

    result.expect_err("unexpected formal attribute rejects");
    assert!(evaluator.trace_output.is_empty());
}

#[test]
fn imported_derivation_alias_excludes_removed_values() {
    let (evaluator, result) = imported_eval(
        br#"args @ { ... }:
          builtins.derivationStrict (
            { name = "summary-test"; system = "x86_64-linux"; builder = "builtin:fetchurl"; } //
            builtins.removeAttrs args [ "ignored" "name" ]
          )"#,
        |path| {
            format!(
                "builtins.deepSeq ((import {}) {{ ignored = builtins.trace \"ignored\" 1; extra = [ 1 ]; }}) 1",
                path.display()
            )
        },
    );
    result.expect("cross-module derivation call evaluates");

    assert!(evaluator.trace_output.is_empty());
    assert!(
        evaluator.stats_snapshot().binding_assembly_elisions() >= 1,
        "stats: {:?}",
        evaluator.stats_snapshot()
    );
    assert!(evaluator.stats_snapshot().thunks_elided() >= 2);
}

#[test]
fn cached_import_preserves_call_summary_symbol_remapping() {
    let root = fs::canonicalize(unique_temp_dir("cached-call-summary"))
        .expect("temp directory canonicalizes");
    let imported_path = root.join("function.nix");
    fs::write(&imported_path, b"{ x, ... }: builtins.seq x 1").expect("import source writes");
    let source = format!(
        "builtins.deepSeq ((import {}) {{ x = [ 1 ]; }}) 1",
        imported_path.display()
    );
    let mut ir = lower(&source);
    crate::compile::annotate_ir(&mut ir).expect("caller analysis succeeds");
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(root.join("parse-cache"));

    let mut first = TreeWalk::with_options(&ir, options.clone());
    first.eval_root().expect("cache-miss call evaluates");
    assert_eq!(first.import_parse_cache_misses, 1);

    let mut second = TreeWalk::with_options(&ir, options);
    second.eval_root().expect("cache-hit call evaluates");
    assert_eq!(second.import_parse_cache_hits, 1);
    assert!(second.stats_snapshot().binding_assembly_elisions() >= 1);
}
