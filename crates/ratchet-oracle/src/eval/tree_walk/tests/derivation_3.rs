//! Tree-walk evaluator tests: derivation 3.

use super::*;
use crate::attrs::repr::AttrSetReprKind;
use crate::heap::HeapGeneration;
use crate::runtime::alloc::{AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint};

#[test]
fn derivation_strict_unions_input_hash_replacement_outputs() {
    let (derivation, input_hashes, shared_hash) = input_hash_replacement_fixture();

    let replacements = TreeWalk::input_hash_replacements(&derivation, &input_hashes);
    assert_eq!(replacements.len(), 1);
    assert_eq!(
        replacements.get(&NixSha256Digest::from_bytes(shared_hash)),
        Some(&BTreeSet::from(["dev".to_owned(), "out".to_owned()]))
    );
}

#[test]
fn derivation_strict_input_hash_replacements_serialize_exact_aterm_order() {
    let (derivation, input_hashes) = distinct_input_hash_serialization_fixture();
    let ir = lower("null");
    let eval = TreeWalk::new(&ir);

    let aterm = eval.derivation_aterm_bytes_with_input_hashes(&derivation, &input_hashes);
    let low_hex = "11".repeat(32);
    let high_hex = "22".repeat(32);
    let expected = format!(
        "Derive([],[(\"{low_hex}\",[\"dev\"]),(\"{high_hex}\",[\"out\"])],[],\":\",\":\",[],[])"
    )
    .into_bytes();

    assert_eq!(aterm, expected);
}

#[test]
fn floating_ca_input_hash_replacements_serialize_exact_aterm_order() {
    let (mut derivation, input_hashes) = distinct_input_hash_serialization_fixture();
    derivation
        .outputs
        .insert("out".to_owned(), nix_compat::derivation::Output::default());
    let output = FloatingCaOutput {
        method: FloatingCaMethod::Recursive,
        hash_algo: nix_compat::nixhash::HashAlgo::Sha256,
    };
    let ir = lower("null");
    let eval = TreeWalk::new(&ir);

    let aterm = eval.floating_ca_derivation_aterm_bytes(&derivation, output, Some(&input_hashes));
    let low_hex = "11".repeat(32);
    let high_hex = "22".repeat(32);
    let expected = format!(
        "Derive([(\"out\",\"\",\"r:sha256\",\"\")],[(\"{low_hex}\",[\"dev\"]),(\"{high_hex}\",[\"out\"])],[],\":\",\":\",[],[])"
    )
    .into_bytes();

    assert_eq!(aterm, expected);
}

#[test]
fn derivation_strict_result_records_dynamic_repr_decision() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let drv_path = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
    )
    .expect("drv store path parses");
    let out_path = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x",
    )
    .expect("out store path parses");
    let dev_path = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"cccccccccccccccccccccccccccccccc-x-dev",
    )
    .expect("dev store path parses");
    let mut derivation = nix_compat::derivation::Derivation::default();
    derivation.outputs.insert(
        "out".to_owned(),
        nix_compat::derivation::Output {
            path: Some(out_path),
            ca_hash: None,
        },
    );
    derivation.outputs.insert(
        "dev".to_owned(),
        nix_compat::derivation::Output {
            path: Some(dev_path),
            ca_hash: None,
        },
    );

    let value = evaluator
        .alloc_derivation_strict_result(
            ir.root,
            span,
            &derivation,
            &drv_path,
            DerivationOutputResolution::StaticPaths,
        )
        .expect("derivation result attrs allocate");

    let attrs = evaluator
        .heap
        .get_attrs(value)
        .expect("derivation result is attrs");
    assert_eq!(attrs.len(), 3);
    let metadata = evaluator
        .heap
        .get_attrs_metadata(value)
        .expect("derivation result metadata exists");
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let lexicographic_keys: Vec<Vec<u8>> = attrs
        .iter_lexicographic()
        .map(|entry| {
            evaluator
                .symbols
                .resolve(entry.key)
                .expect("derivation result key resolves")
                .to_vec()
        })
        .collect();
    assert_eq!(
        lexicographic_keys,
        vec![b"dev".to_vec(), b"drvPath".to_vec(), b"out".to_vec()],
    );
    let snapshot = evaluator
        .attr_telemetry
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 1);
    assert_eq!(snapshot.flat_decisions, 1);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 1);
    let stats = evaluator.attr_telemetry.order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn gc_stress_derivation_strict_result_strings_dispatch_with_registered_entry_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let drv_path = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
    )
    .expect("drv store path parses");
    let out_path = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x",
    )
    .expect("out store path parses");
    let dev_path = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"cccccccccccccccccccccccccccccccc-x-dev",
    )
    .expect("dev store path parses");
    let mut derivation = nix_compat::derivation::Derivation::default();
    derivation.outputs.insert(
        "out".to_owned(),
        nix_compat::derivation::Output {
            path: Some(out_path),
            ca_hash: None,
        },
    );
    derivation.outputs.insert(
        "dev".to_owned(),
        nix_compat::derivation::Output {
            path: Some(dev_path),
            ca_hash: None,
        },
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_derivation_strict_result(
                ir.root,
                span,
                &derivation,
                &drv_path,
                DerivationOutputResolution::StaticPaths,
            )
        })
        .expect("derivation result attrs allocate under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating derivation result strings"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("attrs generation is known"),
        HeapGeneration::Permanent
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("derivation result is attrs");
    assert_eq!(attrs.len(), 3);
    assert!(attrs.iter_by_symbol().all(|entry| {
        entry.value.tag() == ValueTag::String
            && evaluator
                .heap()
                .generation(entry.value)
                .is_ok_and(|generation| generation == HeapGeneration::Permanent)
    }));
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
        ],
        "derivationStrict should dispatch output strings and drvPath string before final generated-attrset dispatch remains blocked"
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 4,
        "derivationStrict should allocate two output strings, the drvPath string, and final attrset under GC stress"
    );
    let final_permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("derivation result allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_derivation_strict_result_string_helper_rewrites_existing_entry_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let key = evaluator
        .intern_builtin_attr_symbol(ir.root, b"previous", span)
        .expect("entry key interns");
    let previous = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("existing entry thunk allocates");
    let mut entries = [AttrEntry::new(key, previous)];

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .alloc_derivation_strict_result_string(
            ir.root,
            span,
            &mut entries,
            NixString::from_bytes(b"next".to_vec()),
        )
        .expect("derivation result string allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(
        !entries[0].value.raw_eq(previous),
        "existing entry root was not rewritten after the result-string safepoint"
    );
    assert_eq!(entries[0].value.tag(), ValueTag::Thunk);
    assert_eq!(
        evaluator
            .heap()
            .generation(entries[0].value)
            .expect("existing entry root generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("allocated result string generation is known"),
        HeapGeneration::Permanent
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

fn input_hash_replacement_fixture() -> (
    nix_compat::derivation::Derivation,
    BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
    [u8; 32],
) {
    let first = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-first.drv",
    )
    .expect("first store path parses");
    let second = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-second.drv",
    )
    .expect("second store path parses");
    let missing = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"cccccccccccccccccccccccccccccccc-missing.drv",
    )
    .expect("missing store path parses");

    let mut derivation = nix_compat::derivation::Derivation::default();
    derivation
        .input_derivations
        .insert(first.clone(), BTreeSet::from(["out".to_owned()]));
    derivation
        .input_derivations
        .insert(second.clone(), BTreeSet::from(["dev".to_owned()]));
    derivation
        .input_derivations
        .insert(missing, BTreeSet::from(["ignored".to_owned()]));

    let shared_hash = [42_u8; 32];
    let mut input_hashes = BTreeMap::new();
    input_hashes.insert(first, DerivationHashModulo::from_sha256_bytes(shared_hash));
    input_hashes.insert(second, DerivationHashModulo::from_sha256_bytes(shared_hash));

    (derivation, input_hashes, shared_hash)
}

fn distinct_input_hash_serialization_fixture() -> (
    nix_compat::derivation::Derivation,
    BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
) {
    let first = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-first.drv",
    )
    .expect("first store path parses");
    let second = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-second.drv",
    )
    .expect("second store path parses");

    let mut derivation = nix_compat::derivation::Derivation {
        system: ":".to_owned(),
        builder: ":".to_owned(),
        ..nix_compat::derivation::Derivation::default()
    };
    derivation
        .input_derivations
        .insert(first.clone(), BTreeSet::from(["out".to_owned()]));
    derivation
        .input_derivations
        .insert(second.clone(), BTreeSet::from(["dev".to_owned()]));

    let mut input_hashes = BTreeMap::new();
    input_hashes.insert(first, DerivationHashModulo::from_sha256_bytes([0x22; 32]));
    input_hashes.insert(second, DerivationHashModulo::from_sha256_bytes([0x11; 32]));

    (derivation, input_hashes)
}

#[test]
fn derivation_strict_supports_structured_floating_content_addressed_derivations() {
    let source = r#"let
             d = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/f0gabys2ih4l8v9npyar6bj5xsa8rj2k-foo.drv","out":"/1w3qgj09cidhvf61hmb2bzyxy64mkcbxzjm6n631m62yjpjhzzvg"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_rejects_invalid_content_addressed_marker() {
    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 __contentAddressed = 1;
               }"#,
    ))
    .expect_err("content-addressed marker must be a bool");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn derivation_strict_supports_impure_derivations() {
    let source = r#"let
             simple = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
             };
             flat = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
               outputHashAlgo = "sha256";
               outputHashMode = "flat";
             };
             structured = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __impure = true;
             };
             multi = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
               outputs = [ "out" "dev" ];
             };
             fixed = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
             base = derivationStrict {
               name = "base";
               system = ":";
               builder = ":";
               __impure = true;
             };
             user = derivationStrict {
               name = "user";
               system = ":";
               builder = ":";
               input = base.out;
             };
           in {
             baseDrv = base.drvPath;
             baseOut = base.out;
             fixedDrv = fixed.drvPath;
             fixedOut = fixed.out;
             flatDrv = flat.drvPath;
             flatOut = flat.out;
             multiDev = multi.dev;
             multiDrv = multi.drvPath;
             multiNames = builtins.attrNames multi;
             multiOut = multi.out;
             simpleCtx = builtins.getContext simple.out;
             simpleDrv = simple.drvPath;
             simpleDrvCtx = builtins.getContext simple.drvPath;
             simpleNames = builtins.attrNames simple;
             simpleOut = simple.out;
             structuredDrv = structured.drvPath;
             structuredOut = structured.out;
             userCtx = builtins.getContext user.out;
             userDrv = user.drvPath;
             userOut = user.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/a0by77ssxmlrqwa9dkfaf04pvbdxzqjg-base.drv","baseOut":"/034l5i2lm0zpg5g58qyq6d01rvazw3yqwzmqkqxl9gcq0z56r4m6","fixedDrv":"/nix/store/3yx7944f4sjjnh56pynw9i73mbmavwb9-foo.drv","fixedOut":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","flatDrv":"/nix/store/5c3xzfl0man0kdk45i398k3avzkk8wvy-foo.drv","flatOut":"/1jw26j2wrfih6x0hh9c6a966sirzvbn4hsnkin2s91s101z48rr7","multiDev":"/04afr1wv95cmfkd5dm12ndybypx7z8dxz06fiwkalm48risqvl10","multiDrv":"/nix/store/9b3swmf9xwz9jv8zh8pn8wplaw3wdqd0-foo.drv","multiNames":["dev","drvPath","out"],"multiOut":"/0c1mqws5832mvaqkx6v4203nf7jz51yn45b5v3pylm5r0j9yfb9m","simpleCtx":{"/nix/store/kxf0wsv4s2sq32qf8babggax9dvv970r-foo.drv":{"outputs":["out"]}},"simpleDrv":"/nix/store/kxf0wsv4s2sq32qf8babggax9dvv970r-foo.drv","simpleDrvCtx":{"/nix/store/kxf0wsv4s2sq32qf8babggax9dvv970r-foo.drv":{"allOutputs":true}},"simpleNames":["drvPath","out"],"simpleOut":"/0fdh6nchbj3w1s0dzdxb44b0cnypwzx7fz5lk4v46603phqkx69y","structuredDrv":"/nix/store/ymkzcxxfrrac7jbyqbxdrkmsic6cykpp-foo.drv","structuredOut":"/1i8lg293jg8xhica7znnava0a639bi5gfj01ymqrsrls5dliiwhf","userCtx":{"/nix/store/d9h67hj8bydbm3lncixzliv1kwl0nw89-user.drv":{"outputs":["out"]}},"userDrv":"/nix/store/d9h67hj8bydbm3lncixzliv1kwl0nw89-user.drv","userOut":"/09jldbl2zzha90yv0zs8jxkj1hm48xh7bxz45qfn45k5n8084k1w"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_impure_derivations_compose_with_other_output_types() {
    let source = r#"let
             impureBase = derivationStrict {
               name = "base";
               system = ":";
               builder = ":";
               __impure = true;
             };
             floatingCa = derivationStrict {
               name = "ca";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               input = impureBase.out;
             };
             downstream = derivationStrict {
               name = "user";
               system = ":";
               builder = ":";
               input = floatingCa.out;
             };
             fixedFromImpure = derivationStrict {
               name = "fixed";
               system = ":";
               builder = ":";
               input = impureBase.out;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
             fixedWithBothMarkers = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
           in {
             baseDrv = impureBase.drvPath;
             baseOut = impureBase.out;
             downstreamCtx = builtins.getContext downstream.out;
             downstreamDrv = downstream.drvPath;
             downstreamOut = downstream.out;
             fixedCtx = builtins.getContext fixedFromImpure.out;
             fixedDrv = fixedFromImpure.drvPath;
             fixedOut = fixedFromImpure.out;
             floatingCaDrv = floatingCa.drvPath;
             floatingCaOut = floatingCa.out;
             markerFixedDrv = fixedWithBothMarkers.drvPath;
             markerFixedOut = fixedWithBothMarkers.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/a0by77ssxmlrqwa9dkfaf04pvbdxzqjg-base.drv","baseOut":"/034l5i2lm0zpg5g58qyq6d01rvazw3yqwzmqkqxl9gcq0z56r4m6","downstreamCtx":{"/nix/store/bqab1ykzfz4x076pcp4vq1jfq5c05a8n-user.drv":{"outputs":["out"]}},"downstreamDrv":"/nix/store/bqab1ykzfz4x076pcp4vq1jfq5c05a8n-user.drv","downstreamOut":"/036ba2igq8ix62kw8q0q11blslb8zrymdajg225m7xbampbi081q","fixedCtx":{"/nix/store/i8f1hl9v5jhk4f268acw73w8nymbwkha-fixed.drv":{"outputs":["out"]}},"fixedDrv":"/nix/store/i8f1hl9v5jhk4f268acw73w8nymbwkha-fixed.drv","fixedOut":"/nix/store/y2bmryv6a5lpk1z2k50b7mddffkf13j4-fixed","floatingCaDrv":"/nix/store/p672mcc8435xhc4bqcf4qf1kn88jzv75-ca.drv","floatingCaOut":"/01rrdjiwi1yd7v29i3981h3brdfnfw8y1wmhvs94m9zyjlh67c6b","markerFixedDrv":"/nix/store/3yx7944f4sjjnh56pynw9i73mbmavwb9-foo.drv","markerFixedOut":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_rejects_invalid_impure_derivations() {
    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __contentAddressed = true;
                 __impure = true;
               }"#,
    ))
    .expect_err("content-addressed impure derivation must be rejected");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DerivationStrict {
            message,
            ..
        } if message == "derivation cannot be both content-addressed and impure"
    ));

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __impure = 1;
               }"#,
    ))
    .expect_err("impure marker must be a bool");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn derivation_strict_rejects_invalid_fixed_output_derivations() {
    for source in [
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "";
                 outputHashAlgo = "";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "";
                 outputHashAlgo = "bogus";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "4374173a8cbe88de152b609f96f46e958bcf65762017474eec5a05ec2bd61530";
                 outputHashAlgo = "bogus";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "4374173a8cbe88de152b609f96f46e958bcf65762017474eec5a05ec2bd61530";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha256";
                 outputHashMode = "bad";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha1";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ "out" "dev" ];
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ "dev" ];
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source))
            .expect_err("invalid fixed-output derivation is rejected");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::DerivationStrict { .. }),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_allows_drv_output_name_but_not_drv_path() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = [ "drv" ];
             };
           in {
             drv = d.drv;
             drvPath = d.drvPath;
             names = builtins.attrNames d;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drv":"/nix/store/bns120nfy7bm27fpsdf7jfkq1laf809f-x-drv","drvPath":"/nix/store/ki88ybnps5knx7lxvicz21x8n9spzhs7-x.drv","names":["drv","drvPath"]}"#.to_vec()
        );

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ "drvPath" ];
               }"#,
    ))
    .expect_err("drvPath is reserved for the derivation path attribute");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DerivationStrict { message, .. }
            if message.contains("invalid derivation output name")
    ));
}

#[test]
fn derivation_strict_rejects_empty_and_duplicate_outputs() {
    for source in [
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ ];
               }"#,
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ "out" "out" ];
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("invalid outputs must be rejected");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::DerivationStrict { .. }),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_allows_drv_path_as_input_output_name() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               input = builtins.appendContext "payload" {
                 "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-input.drv" = {
                   outputs = [ "drvPath" ];
                 };
               };
             };
           in d.drvPath"#;

    let error = eval_whnf_owned(&lower(source))
        .expect_err("unknown input drv should be reported after output-name validation");
    assert!(
        matches!(
            error.kind(),
            TreeWalkErrorKind::DerivationStrict { message, .. }
                if message.contains("is not known")
        ),
        "{error:?}"
    );
}

#[test]
fn derivation_strict_rejects_missing_known_input_output_name() {
    let source = r#"let
             base = derivationStrict {
               name = "base";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
               input = builtins.appendContext "payload" {
                 "/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv" = {
                   outputs = [ "drvPath" ];
                 };
               };
             };
           in builtins.seq base.drvPath d.drvPath"#;

    assert_eq!(
        eval_string_bytes(
            "let base = derivationStrict { name = \"base\"; system = \"x86_64-linux\"; builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder\"; }; in base.drvPath"
        ),
        b"/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv".to_vec()
    );

    let error = eval_whnf_owned(&lower(source))
        .expect_err("known input derivation does not provide drvPath output");
    assert!(
        matches!(
            error.kind(),
            TreeWalkErrorKind::DerivationStrict { message, .. }
                if message.contains("has no output")
        ),
        "{error:?}"
    );
}

#[test]
fn derivation_strict_supports_arguments() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ "a" "b c" 7 true false null ];
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/jd4xrrbkljw5cjzl1cl5aid034ax3r3r-x.drv","out":"/nix/store/wbpvl18k2swqk8m05048r544h4kxb3hc-x"}"#.to_vec()
        );

    let nested = r#"let
             simple = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ "a b" "c" ];
             };
             nested = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ [ "a" "b" ] "c" ];
             };
           in {
             nested = nested.drvPath;
             same = simple.drvPath == nested.drvPath;
             simple = simple.drvPath;
           }"#;

    assert_eq!(
            eval_json_bytes(nested),
            br#"{"nested":"/nix/store/5wq01zb7i3yxn0aj6l1snyflpzvc704g-x.drv","same":true,"simple":"/nix/store/5wq01zb7i3yxn0aj6l1snyflpzvc704g-x.drv"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_observes_argument_contexts_as_inputs() {
    let source = r#"let
             base = derivationStrict {
               name = "base";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
               args = [ "${base.out}" ];
             };
           in {
             baseDrv = base.drvPath;
             baseOut = base.out;
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv","baseOut":"/nix/store/c9hhy38jds9ffzzqwkb50vrv2pi8x614-base","drvPath":"/nix/store/jpaibv0aq71nimqkaa2zgzhyjx3jsdqm-x.drv","out":"/nix/store/v9psivi4r812mfl72k0y62b61r1f6gvb-x"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_first_class_values_call_builtin() {
    for source in [
        r#"let
                 f = derivationStrict;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in builtins.hasAttr "out" d"#,
        r#"let
                 f = builtins.derivationStrict;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in builtins.hasAttr "drvPath" d"#,
        r#"with { derivationStrict = x: x; }; let
                 f = derivationStrict;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in builtins.hasAttr "out" d"#,
    ] {
        assert_eq!(eval(source).as_bool(), Ok(true), "{source}");
    }

    let ir = lower("with { derivationStrict = x: x; }; let f = derivationStrict; in f 1");
    let error = eval_whnf_owned(&ir).expect_err("derivationStrict remains unshadowable");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn derivation_strict_observes_contexts_as_inputs() {
    let source = r#"let
             base = derivationStrict {
               name = "base";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
             opaque = builtins.appendContext "src" {
               "/nix/store/cccccccccccccccccccccccccccccccc-src" = { path = true; };
             };
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
               input = "${base.out}${opaque}";
             };
           in {
             baseDrv = base.drvPath;
             baseOut = base.out;
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv","baseOut":"/nix/store/c9hhy38jds9ffzzqwkb50vrv2pi8x614-base","drvPath":"/nix/store/g517w28ijkgqc1p2hqwrnjwh1lblnavz-x.drv","out":"/nix/store/7alc4f6hbky5mkzhqqsmyw7mk354i4mh-x"}"#.to_vec()
        );
}

#[test]
fn derivation_coercion_preserves_out_path_context() {
    assert_eq!(
        eval(
            r#"let
                     strict = derivationStrict {
                       name = "x";
                       system = "x86_64-linux";
                       builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                     };
                     drv = {
                       type = "derivation";
                       name = "x";
                       drvPath = strict.drvPath;
                       outPath = strict.out;
                     };
                     rendered = "${drv}";
                     ctx = builtins.getContext rendered;
                   in rendered == strict.out && builtins.hasAttr strict.drvPath ctx"#
        )
        .as_bool(),
        Ok(true)
    );
}
