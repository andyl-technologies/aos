//! Phase 4 Chunk E cross-module call-summary tests.

use super::*;

fn evaluate_import_call(ir: &Ir, root: &Path) -> EvalOutcome {
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    eval_whnf_owned_with_options(ir, options).expect("import call evaluates")
}

fn string_result(outcome: &EvalOutcome) -> Vec<u8> {
    outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is a string")
        .bytes()
        .to_vec()
}

#[test]
fn imported_mkderivation_summary_elides_only_surviving_total_bindings() {
    let root = fs::canonicalize(unique_temp_dir("chunk-e-mkderivation"))
        .expect("temp directory canonicalizes");
    fs::write(
        root.join("callee.nix"),
        br#"args @ { name, ignored ? null, ... }:
          builtins.derivation (
            { inherit name; builder = "builtin:fetchurl"; system = "x86_64-linux"; } //
            builtins.removeAttrs args [ "ignored" ]
          )"#,
    )
    .expect("callee writes");
    let source = r#"((import ./callee.nix) (
      {
        name = builtins.trace "shadowed-name" "left";
        shadowed = builtins.trace "shadowed-value" "left";
      } // {
        name = "chunk-e";
        shadowed = [ "right" ];
        total = [ "one" "two" ];
        ignored = builtins.trace "ignored" null;
        late = builtins.trace "late" "value";
        zed = builtins.trace "zed" "value";
      }
    )).drvPath"#;

    let conservative = evaluate_import_call(&lower(source), &root);
    let mut analyzed_ir = lower(source);
    crate::compile::annotate_ir(&mut analyzed_ir).expect("caller analysis succeeds");
    let analyzed = evaluate_import_call(&analyzed_ir, &root);

    assert_eq!(string_result(&analyzed), string_result(&conservative));
    assert_eq!(analyzed.trace_output(), conservative.trace_output());
    let messages = analyzed
        .trace_output()
        .iter()
        .map(EvalTraceOutput::message)
        .collect::<Vec<_>>();
    assert_eq!(messages, [b"late".as_slice(), b"zed".as_slice()]);
    assert!(
        analyzed.stats().binding_assembly_elisions()
            > conservative.stats().binding_assembly_elisions(),
        "cross-module totals should add assembly elisions ({} vs {})",
        analyzed.stats().binding_assembly_elisions(),
        conservative.stats().binding_assembly_elisions(),
    );
    assert!(
        analyzed.stats().thunks_allocated() < conservative.stats().thunks_allocated(),
        "cross-module totals should allocate fewer thunks ({} vs {})",
        analyzed.stats().thunks_allocated(),
        conservative.stats().thunks_allocated(),
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}
