//! Split-out analysis-soundness tests (part_1). See parent module.
use super::*;

#[test]
fn single_entry_storage_preserves_observables_and_is_exercised() {
    // A consumed-position once-used binding takes single-entry storage in
    // the annotated run; per-call frames re-allocate it, so the trace count
    // must match the conservative update-thunk schedule exactly.
    let source = r#"let f = z: (let x = builtins.trace "t" [ 1 2 ];
                                 in builtins.length x + z);
                    in f 1 + f 2"#;
    let json_source = format!("builtins.toJSON ({source})");
    let conservative_ir = lower(&json_source);
    let mut annotated_ir = lower(&json_source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");

    let mut conservative_eval =
        TreeWalk::with_options(&conservative_ir, TreeWalkOptions::default());
    let conservative_value = conservative_eval
        .eval_root()
        .expect("conservative evaluates");
    let mut annotated_eval = TreeWalk::with_options(&annotated_ir, TreeWalkOptions::default());
    let annotated_value = annotated_eval.eval_root().expect("annotated evaluates");

    let conservative_json = conservative_eval
        .heap
        .get_string(conservative_value)
        .expect("toJSON returns a string")
        .bytes()
        .to_vec();
    let annotated_json = annotated_eval
        .heap
        .get_string(annotated_value)
        .expect("toJSON returns a string")
        .bytes()
        .to_vec();
    assert_eq!(annotated_json, conservative_json);
    assert_eq!(
        annotated_eval.trace_output, conservative_eval.trace_output,
        "single-entry storage must not change trace multiplicity"
    );

    assert_eq!(conservative_eval.stats().single_entry_thunks_allocated(), 0);
    assert_eq!(
        annotated_eval.stats().single_entry_thunks_allocated(),
        2,
        "one single-entry allocation per call frame"
    );
    assert_eq!(
        annotated_eval.stats().single_entry_thunks_forced(),
        2,
        "each single-entry thunk forced exactly once"
    );
}

#[test]
fn analysis_annotations_preserve_unforced_identity_call_results() {
    // An identity-shaped callee returns its argument unforced; the argument
    // may only be treated as demanded when the call's own value is forced.
    for source in [
        r#"builtins.length (builtins.map (y: (x: x) (builtins.throw "a")) [1])"#,
        r#"builtins.length [ ((x: x) (builtins.throw "a")) ]"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn capture_plans_match_runtime_slot_reads() {
    // FV-5 validation: every captured-prefix slot read performed while a
    // planned thunk body runs must be inside the site's flat capture plan.
    let mut total_reads_checked = 0;
    for source in [
        "let a = 1 + 1; b = a + 2; in b + a",
        "(x: y: x + y) 3 4",
        "let f = x: x + 1; in f (f 2)",
        "let a = 1 + 1; in (x: a + x) 5",
        "rec { m = n + 1; n = 2; }.m",
        "let a = 1 + 1; in let b = a + 1; in (x: a + b + x) 1",
        "({ x ? 1, y ? x }: x + y) {}",
        "builtins.length (builtins.map (e: e + 1) [ 1 2 3 ])",
        "let xs = [ 1 2 3 ]; in builtins.foldl' (acc: e: acc + e) 0 xs",
        r#"let s = "a" + "b"; t = s + "c"; in builtins.stringLength t"#,
    ] {
        let mut ir = lower(source);
        crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
        let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::default());
        evaluator.enable_capture_plan_validation();
        evaluator.eval_root().expect("source evaluates");
        assert!(
            evaluator.capture_plan_violations().is_empty(),
            "{source}: {:?}",
            evaluator.capture_plan_violations()
        );
        total_reads_checked += evaluator.capture_plan_reads_checked();
    }
    assert!(
        total_reads_checked > 0,
        "the validation harness must observe captured-prefix reads"
    );
}

#[test]
fn flat_capture_plans_replace_outer_frames_after_publication() {
    let mut ir = lower("let a = 1 + 1; in x: a + x");
    crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    let value = evaluator.eval_root().expect("lambda evaluates");
    let lambda = evaluator
        .heap()
        .get_lambda(value)
        .expect("root is a heap-owned lambda");
    let env = lambda.env();

    assert!(env.frames().is_empty(), "flat sites retain no outer frames");
    let flat = env.flat_base().expect("lambda consumes its flat plan");
    assert!(
        flat.inline_owner().raw_eq(value),
        "the closure value must own its inlined capture tail"
    );
    let values = evaluator
        .flat_capture_values(flat)
        .expect("flat capture values resolve");
    assert_eq!(flat.frame_count(), 1);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].tag(), ValueTag::Thunk);
    let campaign = evaluator.stats_snapshot().campaign();
    assert!(campaign.flat_env_captures > 0);
    assert!(campaign.flat_env_capture_values > 0);
}

#[test]
fn recursive_assembly_flattens_only_after_publication() {
    let mut ir = lower("rec { a = 1; b = a; }");
    crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
    let b = symbol_for(&ir, b"b");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    let value = evaluator.eval_root().expect("recursive attrset evaluates");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("root is a heap-owned attrset");
    let b_value = attrs.get(b).expect("b exists");
    let thunk = evaluator
        .heap()
        .get_thunk(b_value)
        .expect("b remains a suspended thunk");
    let env = thunk.env().expect("node thunk has a lexical environment");

    assert!(
        env.frames().is_empty(),
        "published recursive closures must release their assembly frame"
    );
    let flat = env
        .flat_base()
        .expect("published recursive closure consumes its flat plan");
    assert!(
        flat.inline_owner().raw_eq(b_value),
        "publication must point the environment at its owning closure"
    );
    let values = evaluator
        .flat_capture_values(flat)
        .expect("flat capture values resolve");
    assert_eq!(flat.frame_count(), 1);
    assert_eq!(values.len(), 1);
}

#[test]
fn capture_plan_validation_detects_understated_plans() {
    // Harness self-check: corrupt one thunk site's plan to claim an empty
    // free-variable set; the body's real captured-prefix read must surface
    // as a violation.
    let source = "let a = 1 + 1; b = a + 2; in b";
    let mut ir = lower(source);
    crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
    let mut corrupted = 0;
    for index in 0..ir.arena.nodes().len() as u32 {
        let id = crate::compile::IrId::new(index);
        let node = ir.arena.node(id).expect("node exists");
        if node.kind != crate::compile::IrKind::ThunkAlloc {
            continue;
        }
        if let Some(crate::compile::CapturePlan::Flat(slots)) = ir.facts.capture_plan(id)
            && !slots.is_empty()
        {
            ir.facts
                .set_capture_plan(id, Some(crate::compile::CapturePlan::Flat(Box::new([]))));
            corrupted += 1;
        }
    }
    assert!(corrupted > 0, "corpus must contain a capturing thunk site");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    evaluator.enable_capture_plan_validation();
    evaluator.eval_root().expect("source evaluates");
    assert!(
        !evaluator.capture_plan_violations().is_empty(),
        "an understated plan must be detected"
    );
}

/// Measurement probe: aggregates the FV-5 free-variable histogram over every
/// `.nix` file below `AOS_NIX_CAPTURE_HISTOGRAM_DIR` (recursively) and prints
/// the distribution. Ignored by default; run explicitly:
///
/// ```text
/// AOS_NIX_CAPTURE_HISTOGRAM_DIR=/path/to/repo cargo test -p ratchet-oracle \
///   capture_plan_free_var_histogram -- --ignored --nocapture
/// ```
#[test]
#[ignore = "measurement probe; needs AOS_NIX_CAPTURE_HISTOGRAM_DIR"]
fn capture_plan_free_var_histogram_over_corpus() {
    use crate::compile::analysis::{
        FREE_VAR_HISTOGRAM_BUCKETS, annotate_capture_plans, annotate_cardinality, annotate_escape,
        annotate_strictness,
    };
    let Ok(root) = std::env::var("AOS_NIX_CAPTURE_HISTOGRAM_DIR") else {
        panic!("set AOS_NIX_CAPTURE_HISTOGRAM_DIR to the corpus root");
    };
    let mut histogram = [0usize; FREE_VAR_HISTOGRAM_BUCKETS];
    let mut lambda_sites = 0usize;
    let mut thunk_sites = 0usize;
    let mut flat = 0usize;
    let mut shared = 0usize;
    let mut silent = 0usize;
    let mut max_free = 0usize;
    let mut files = 0usize;
    let mut skipped = 0usize;
    let mut phase_times = [std::time::Duration::ZERO; 4];
    let mut stack = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == ".git") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "nix") {
                continue;
            }
            let Ok(source) = std::fs::read(&path) else {
                skipped += 1;
                continue;
            };
            let Ok(parsed) = parse_bytes(&source) else {
                skipped += 1;
                continue;
            };
            let Ok(resolved) = resolve_ast(parsed) else {
                skipped += 1;
                continue;
            };
            let Ok(mut ir) = aos_nix_dialect::nix_lower(resolved) else {
                skipped += 1;
                continue;
            };
            let started = std::time::Instant::now();
            if annotate_strictness(&mut ir).is_err() {
                skipped += 1;
                continue;
            }
            phase_times[0] += started.elapsed();
            let started = std::time::Instant::now();
            if annotate_cardinality(&mut ir).is_err() {
                skipped += 1;
                continue;
            }
            phase_times[1] += started.elapsed();
            let started = std::time::Instant::now();
            if annotate_escape(&mut ir).is_err() {
                skipped += 1;
                continue;
            }
            phase_times[2] += started.elapsed();
            let started = std::time::Instant::now();
            let Ok(report) = annotate_capture_plans(&mut ir) else {
                skipped += 1;
                continue;
            };
            phase_times[3] += started.elapsed();
            files += 1;
            for (bucket, count) in report.free_var_histogram.iter().enumerate() {
                histogram[bucket] += count;
            }
            lambda_sites += report.lambda_sites;
            thunk_sites += report.thunk_sites;
            flat += report.flat_plans;
            shared += report.shared_chain_plans;
            silent += report.pure_silent_thunk_bodies;
            max_free = max_free.max(report.max_free_vars);
        }
    }
    println!("files analyzed: {files} (skipped {skipped})");
    println!("lambda sites: {lambda_sites}, thunk sites: {thunk_sites}");
    println!("flat plans: {flat}, shared-chain plans: {shared}");
    println!("pure-silent thunk bodies (call-by-name candidates): {silent}");
    println!("max free vars: {max_free}");
    println!("analysis times [strict, cardinality, escape, capture]: {phase_times:?}");
    let total: usize = histogram.iter().sum();
    let mut cumulative = 0usize;
    for (size, count) in histogram.iter().enumerate() {
        cumulative += count;
        let label = if size == FREE_VAR_HISTOGRAM_BUCKETS - 1 {
            format!("{size}+")
        } else {
            size.to_string()
        };
        println!(
            "free={label:>3}: {count:>7} ({:5.1}% cum {:5.1}%)",
            100.0 * *count as f64 / total.max(1) as f64,
            100.0 * cumulative as f64 / total.max(1) as f64,
        );
    }
    assert!(files > 0, "corpus contained no analyzable .nix files");
}

/// Pins the `derivationStrict` dialect-op key the core strictness analysis
/// mirrors (`ratchet-core` cannot depend on the dialect crate). The key is
/// serialized raw into persisted `ir.bin` artifacts, so it is format-stable
/// and the mirror constant may rely on it.
#[test]
fn derivation_strict_dialect_op_is_format_stable() {
    assert_eq!(
        aos_nix_dialect::NIX_OP_DERIVATION_STRICT,
        crate::compile::IrDialectOp::new(1),
    );
}

#[test]
fn analysis_annotations_preserve_derivation_strict_error_identity_and_order() {
    for source in [
        // `name` is forced first: its error wins over every other attribute.
        r#"builtins.derivationStrict {
             name = builtins.throw "name-error";
             builder = builtins.throw "builder-error";
             system = "s";
           }"#,
        // Sorted force order between two throwing attributes: `builder`
        // precedes `system` lexicographically in both schedules.
        r#"builtins.derivationStrict {
             name = "ok";
             builder = builtins.throw "first-sorted";
             system = builtins.throw "second-sorted";
           }"#,
        // A missing `name` throws before any attribute value is forced.
        r#"builtins.derivationStrict {
             builder = builtins.throw "builder-error";
             system = "s";
           }"#,
        // Non-string name: the type error fires after the first force.
        r#"builtins.derivationStrict {
             name = 1 + 2;
             builder = builtins.throw "builder-error";
             system = "s";
           }"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_derivation_strict_ignore_nulls_interplay() {
    for source in [
        // Null attributes are forced before the `__ignoreNulls` drop.
        r#"(builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             __ignoreNulls = true;
             dropped = null;
             extra = [ 1 2 ];
           }).drvPath"#,
        // A throwing `__ignoreNulls` fires in its pre-loop force position.
        r#"builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             __ignoreNulls = builtins.throw "ignore-nulls";
           }"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_derivation_strict_structured_attrs() {
    for source in [
        r#"(builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             __structuredAttrs = true;
             nested = { a = [ 1 ]; b = "x"; };
             outputs = [ "out" "dev" ];
           }).drvPath"#,
        r#"builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             __structuredAttrs = builtins.throw "structured";
           }"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_derivation_strict_binding_sources() {
    for source in [
        // `inherit (src) attr` values route through the shared-receiver
        // select-thunk path and must stay as lazy as before.
        r#"let src = { dep = builtins.throw "inherited"; };
           in builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             inherit (src) dep;
           }"#,
        // Dynamic keys mixed with static ones decline the eager plan.
        r#"builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             ${"dy" + "namic"} = builtins.throw "dynamic-value";
           }"#,
        // Formal defaults are populated by the same order-sensitive
        // assembler and must stay lazy.
        r#"({ x ? builtins.throw "default" }: builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
           }) {}"#,
        // Recursive-let forward references feeding a derivation literal.
        r#"let n = "a" + b; b = "bc";
           in (builtins.derivationStrict {
             name = n;
             builder = "b";
             system = "s";
             deps = [ 1 2 3 ];
           }).drvPath"#,
        // A rec literal argument declines seeding but must stay equivalent.
        r#"(builtins.derivationStrict (rec {
             name = "d" + "x";
             builder = "b";
             system = "s";
             alias = name;
           })).drvPath"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_drive_binding_assembly_elision() {
    let source = r#"(builtins.derivationStrict {
        name = "d-" + "1";
        builder = "/bin/sh";
        system = "x86_64-linux";
        args = [ "-c" "true" ];
    }).drvPath"#;
    let conservative_ir = lower(source);
    let mut annotated_ir = lower(source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");

    let conservative = eval_whnf_owned(&conservative_ir).expect("conservative evaluates");
    let annotated = eval_whnf_owned(&annotated_ir).expect("annotated evaluates");

    let conservative_path = conservative
        .heap()
        .get_string(conservative.value())
        .expect("drvPath is a string")
        .bytes()
        .to_vec();
    let annotated_path = annotated
        .heap()
        .get_string(annotated.value())
        .expect("drvPath is a string")
        .bytes()
        .to_vec();
    assert_eq!(annotated_path, conservative_path);

    // The non-total first-forced `name` and the total `args` list evaluate
    // directly into their slots; the conservative plan allocates instead.
    assert_eq!(conservative.stats().binding_assembly_elisions(), 0);
    assert!(
        annotated.stats().binding_assembly_elisions() >= 2,
        "expected at least two assembly elisions, got {}",
        annotated.stats().binding_assembly_elisions(),
    );
    assert!(
        annotated.stats().thunks_allocated() < conservative.stats().thunks_allocated(),
        "eager assembly must allocate fewer thunks ({} vs {})",
        annotated.stats().thunks_allocated(),
        conservative.stats().thunks_allocated(),
    );
}

#[test]
fn dynamic_attr_name_may_force_pending_flat_captures() {
    // Regression coverage for the FV-5 publication boundary (RFC-0007
    // task #8): a dynamic attribute *name* evaluates inside the enclosing
    // attrset's order-sensitive assembly window, so a flat-planned record
    // allocated by the name expression is deferred to the outermost
    // publication boundary — and then legitimately forced (here via `seq`
    // on its fields) before that boundary is reached. The I1 force path
    // promotes the forced thunk to a shared payload, so publication must
    // treat it as `ForcedBeforePublication` rather than a lost capture.
    // Pre-fix this tripped `flat_capture.rs`'s debug assert.
    let source = r#"let
      mk = c: { path = c; keep = c; };
    in {
      ${let d = mk 5; in builtins.seq d.path (builtins.seq d.keep "k")} = 1;
    }"#;
    assert_annotated_json_matches_conservative(source);
}

#[test]
fn module_system_option_map_forces_pending_flat_captures() {
    // The motivating shape from `lib/modules.nix`: `collectOptions` builds
    // declaration records (`path = prefix ++ [ name ]`) inside binding
    // assembly, and the option-map `foldl'`'s dynamic attribute name forces
    // each record's `path` while later assembly windows are still open.
    // Distilled evalModules-style fixture so the module-system shape class
    // stays covered by the parity battery.
    let source = r#"let
      collect = prefix: decls:
        builtins.concatLists (builtins.map (
          name: let
            decl = {
              path = prefix ++ [ name ];
              value = decls.${name};
            };
          in [ decl ]
        ) (builtins.attrNames decls));
      allDecls = collect [ "options" ] { a = 1; b = 2; };
      optionMap = builtins.foldl' (
        acc: decl: acc // { ${builtins.concatStringsSep "." decl.path} = decl.value; }
      ) {} allDecls;
    in optionMap"#;
    assert_annotated_json_matches_conservative(source);
}
