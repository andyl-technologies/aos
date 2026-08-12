//! Tree-walk evaluator tests: derivation 1.

use super::*;

#[test]
fn has_attr_detects_single_static_keys_without_forcing_values() {
    assert_eq!(eval("({ a = 1; } ? a)").as_bool(), Ok(true));
    assert_eq!(eval("({ a = 1; } ? z)").as_bool(), Ok(false));
    assert_eq!(eval("({ a = 1 / 0; } ? a)").as_bool(), Ok(true));
    assert_eq!(eval("({ a = 1 / 0; } ? z)").as_bool(), Ok(false));

    let receiver_error = lower("((1 / 0) ? a)");
    let error = eval_whnf_owned(&receiver_error).expect_err("has-attr forces the receiver first");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn has_attr_returns_false_for_non_attr_path_values() {
    assert_eq!(eval("(1 ? a)").as_bool(), Ok(false));
    assert_eq!(eval("({} ? a.b.c)").as_bool(), Ok(false));
    assert_eq!(eval("({ a = 1; } ? a.b)").as_bool(), Ok(false));
}

#[test]
fn has_attr_evaluates_nested_static_and_dynamic_paths() {
    assert_eq!(eval("({ a = { b = 1 / 0; }; } ? a.b)").as_bool(), Ok(true));
    assert_eq!(eval("({ a = {}; } ? a.b)").as_bool(), Ok(false));
    assert_eq!(eval("({ a = {}; } ? a.b.c)").as_bool(), Ok(false));
    assert_eq!(eval("({ a = 1; } ? ${\"a\"})").as_bool(), Ok(true));
    assert_eq!(eval("({ ab = 1; } ? ${\"a\" + \"b\"})").as_bool(), Ok(true));
    assert_eq!(eval("({} ? ${\"a\"}.${1 / 0})").as_bool(), Ok(false));
    assert_eq!(eval("(1 ? ${\"a\"})").as_bool(), Ok(false));

    let error_ir = lower("({ a = 1 / 0; } ? a.b)");
    let error = eval_whnf_owned(&error_ir).expect_err("intermediate thunk errors win");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let null_key = lower("({ a = 1; } ? ${null})");
    let null_node = null_key
        .arena
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.kind == IrKind::Null)
        .map(|(index, _)| IrId::new(index as u32))
        .expect("null key expression exists");
    let null_error = eval_whnf_owned(&null_key).expect_err("has-attr dynamic null key is invalid");

    assert_eq!(
        null_error.kind(),
        TreeWalkErrorKind::Type {
            id: null_node,
            expected: "string",
            actual: ValueTag::Null,
        }
    );
    assert_eq!(
        null_error.span(),
        null_key
            .arena
            .node(null_node)
            .expect("null key expression exists")
            .span
    );

    for (source, actual) in [
        (
            "({ value = 9; } ? ${ { __toString = self: \"value\"; } })",
            ValueTag::Attrs,
        ),
        ("({ \"/tmp/x\" = 5; } ? ${/tmp/x})", ValueTag::Path),
    ] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("dynamic has-attr requires string keys");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "string",
                actual: observed,
                ..
            } if observed == actual
        ));
    }

    let context_key = lower(
        r#"({ name = 7; } ? ${builtins.appendContext "name" {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source" = { path = true; };
               }})"#,
    );
    let error = eval_whnf_owned(&context_key).expect_err("dynamic has-attr rejects string context");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "dynamic attribute name",
            ..
        }
    ));
}

#[test]
fn has_attr_evaluates_receiver_and_reached_dynamic_keys_in_order() {
    let ir = lower("((1 / 0) ? ${\"a\"})");
    let error = eval_whnf_owned(&ir).expect_err("receiver errors before dynamic key success");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    let division = ir
        .arena
        .nodes()
        .iter()
        .find(|node| node.kind == IrKind::BinOp)
        .expect("division node exists");
    assert_eq!(error.span(), division.span);

    let dynamic_error = lower("({} ? ${1 / 0})");
    let error =
        eval_whnf_owned(&dynamic_error).expect_err("first dynamic has-attr key is still evaluated");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn list_concat_type_checks_operands_left_to_right() {
    let lhs_ir = lower("1 ++ (1 / 0)");
    let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
    let IrData::Binary { lhs, .. } = root.data else {
        panic!("concat root has binary payload");
    };
    let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

    let error = eval_whnf_owned(&lhs_ir).expect_err("integer lhs is invalid before rhs");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: lhs,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), lhs_span);

    let rhs_ir = lower("[] ++ 1");
    let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("concat root has binary payload");
    };
    let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&rhs_ir).expect_err("integer rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), rhs_span);

    let rhs_error_ir = lower("[] ++ (1 / 0)");
    let root = rhs_error_ir
        .arena
        .node(rhs_error_ir.root)
        .expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("concat root has binary payload");
    };
    let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn attr_update_type_checks_operands_left_to_right() {
    let lhs_ir = lower("1 // (1 / 0)");
    let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
    let IrData::Binary { lhs, .. } = root.data else {
        panic!("update root has binary payload");
    };
    let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

    let error = eval_whnf_owned(&lhs_ir).expect_err("integer lhs is invalid before rhs");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: lhs,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), lhs_span);

    let rhs_ir = lower("{} // 1");
    let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("update root has binary payload");
    };
    let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&rhs_ir).expect_err("integer rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), rhs_span);

    let rhs_error_ir = lower("{} // (1 / 0)");
    let root = rhs_error_ir
        .arena
        .node(rhs_error_ir.root)
        .expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("update root has binary payload");
    };
    let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn non_owning_eval_rejects_list_concat_heap_values() {
    let ir = lower("[] ++ []");
    let error = eval_whnf(&ir).expect_err("list concat value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::List,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );
}

#[test]
fn non_owning_eval_rejects_attr_update_heap_values() {
    let ir = lower("{} // {}");
    let error = eval_whnf(&ir).expect_err("attr update value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::Attrs,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );
}

#[test]
fn string_add_concatenates_heap_strings() {
    let outcome = eval_whnf_owned(&lower("\"a\" + \"b\"")).expect("string add evaluates");
    let value = outcome.value();

    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        outcome
            .heap()
            .get_string(value)
            .expect("string add result is heap-owned")
            .bytes(),
        b"ab"
    );

    let escaped =
        eval_whnf_owned(&lower("\"a\\n\" + \"b\"")).expect("escaped string add evaluates");
    assert_eq!(
        escaped
            .heap()
            .get_string(escaped.value())
            .expect("escaped add result is heap-owned")
            .bytes(),
        b"a\nb"
    );
}

#[test]
fn string_add_store_coerces_path_rhs() {
    let (dir, path) = temp_file_with_bytes("string-add-path", b"abc");
    let path = path_source(&path);
    let store_path = "/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt";

    assert_eq!(
        eval_string_bytes(&format!("\"prefix-\" + {path}")),
        format!("prefix-{store_path}").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON (builtins.getContext (\"prefix-\" + {path}))"
        )),
        br#"{"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt":{"path":true}}"#
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "\"prefix-\" + {{ __toString = self: {path}; outPath = 1 / 0; }}"
        )),
        format!("prefix-{store_path}").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("\"prefix-\" + {{ outPath = {path}; }}")),
        format!("prefix-{store_path}").as_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn string_add_rejects_missing_path_rhs() {
    let dir = unique_temp_dir("string-add-missing-path");
    let path = path_source(&dir.join("missing.txt"));
    let ir = lower(&format!("\"prefix-\" + {path}"));
    let error = eval_whnf_owned(&ir).expect_err("missing path rhs cannot be copied to store");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::SourcePathArchive { .. }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_add_concatenates_raw_paths_and_context_free_strings() {
    let dir = unique_temp_dir("path-add");
    let base = dir.join("base");
    fs::create_dir(&base).expect("base directory creates");
    let suffix = dir.join("suffix.txt");
    fs::write(&suffix, b"abc").expect("suffix file writes");
    let base = path_source(&base);
    let suffix = path_source(&suffix);

    assert_eq!(
        eval_string_bytes(&format!("builtins.typeOf ({base} + \"/child\")")),
        b"path"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString ({base} + \"/child\")")),
        format!("{base}/child").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString ({base} + \"child\")")),
        format!("{base}child").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString ({base} + \"/../sibling\")")),
        path_source(&dir.join("sibling")).as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString ({base} + {suffix})")),
        format!("{base}{suffix}").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toString ({base} + {{ __toString = self: \"/hook\"; outPath = 1 / 0; }})"
        )),
        format!("{base}/hook").as_bytes()
    );

    let ir = lower(&format!(
        r#"{base} + (builtins.appendContext "/child" {{
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = {{ path = true; }};
            }})"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("path append rejects string context");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "path addition",
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn string_add_unions_contexts() {
    assert_eq!(
        eval(
            r#"let
                     withCtx = text: path: builtins.appendContext text {
                       ${path} = { path = true; };
                     };
                     aPath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                     bPath = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
                     result = withCtx "a" aPath + withCtx "b" bPath;
                     ctx = builtins.getContext result;
                   in result == "ab" && builtins.hasAttr aPath ctx && builtins.hasAttr bPath ctx"#
        )
        .as_bool(),
        Ok(true)
    );

    let ir = lower("1");
    let mut evaluator = TreeWalk::new(&ir);
    let node = *ir.arena.node(ir.root).expect("root exists");
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let output =
        ContextElement::single_output(b"/nix/store/derivation.drv".to_vec(), b"out".to_vec())
            .expect("output context is valid");
    let left = evaluator
        .heap
        .alloc_string(NixString::new(
            b"hello".to_vec(),
            StringContext::singleton(source.clone()).expect("source context allocates"),
        ))
        .expect("left string allocates");
    let right = evaluator
        .heap
        .alloc_string(NixString::new(
            b" world".to_vec(),
            StringContext::singleton(output.clone()).expect("output context allocates"),
        ))
        .expect("right string allocates");

    let result = evaluator
        .concat_strings(ir.root, &node, left, right)
        .expect("strings concatenate");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result string is heap-owned");

    assert_eq!(string.bytes(), b"hello world");
    assert_eq!(string.context().len(), 2);
    assert!(string.context().contains(&source));
    assert!(string.context().contains(&output));
}

#[test]
fn derivation_strict_returns_context_bearing_outputs() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
           in {
             drvContext = builtins.getContext d.drvPath;
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             out = d.out;
             outContext = builtins.getContext d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvContext":{"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv":{"allOutputs":true}},"drvPath":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","names":["drvPath","out"],"out":"/nix/store/ss8z7hsjimnxam6mx6z8znm64qrk08cn-x","outContext":{"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv":{"outputs":["out"]}}}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_returns_default_output_derivation_shape() {
    let source = r#"let
             d = derivation {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
           in {
             allLen = builtins.length d.all;
             drvAttrs = builtins.attrNames d.drvAttrs;
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             outNames = builtins.attrNames d.out;
             pathOut = d.outPath;
             outputName = d.outputName;
             rendered = "${d}";
             renderedContext = builtins.getContext "${d}";
             kind = d.type;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"allLen":1,"drvAttrs":["builder","name","system"],"drvPath":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","kind":"derivation","names":["all","builder","drvAttrs","drvPath","name","out","outPath","outputName","system","type"],"outNames":["all","builder","drvAttrs","drvPath","name","out","outPath","outputName","system","type"],"outputName":"out","pathOut":"/nix/store/ss8z7hsjimnxam6mx6z8znm64qrk08cn-x","rendered":"/nix/store/ss8z7hsjimnxam6mx6z8znm64qrk08cn-x","renderedContext":{"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv":{"outputs":["out"]}}}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_preserves_custom_outputs_and_recursive_aliases() {
    let source = r#"let
             d = derivation {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = [ "out" "dev" ];
             };
           in {
             allLen = builtins.length d.all;
             allOutputNames = builtins.map (x: x.outputName) d.all;
             devNested = d.dev.out.dev.dev.outPath;
             devOutPath = d.dev.outPath;
             drvAttrs = builtins.attrNames d.drvAttrs;
             names = builtins.attrNames d;
             outNested = d.out.dev.out.outPath;
             pathOut = d.outPath;
             outputs = d.outputs;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"allLen":2,"allOutputNames":["out","dev"],"devNested":"/nix/store/phkb0v7mn27i2c5y0qg9d18wvgch5x2w-x-dev","devOutPath":"/nix/store/phkb0v7mn27i2c5y0qg9d18wvgch5x2w-x-dev","drvAttrs":["builder","name","outputs","system"],"names":["all","builder","dev","drvAttrs","drvPath","name","out","outPath","outputName","outputs","system","type"],"outNested":"/nix/store/kpxa7fq9k2f03c5mn9ipsqjs09lnj1gj-x","outputs":["out","dev"],"pathOut":"/nix/store/kpxa7fq9k2f03c5mn9ipsqjs09lnj1gj-x"}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_supports_non_out_first_output() {
    let source = r#"let
             d = derivation {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = [ "dev" ];
             };
           in {
             allLen = builtins.length d.all;
             hasDev = builtins.hasAttr "dev" d;
             hasOut = builtins.hasAttr "out" d;
             names = builtins.attrNames d;
             pathOut = d.outPath;
             outputName = d.outputName;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"allLen":1,"hasDev":true,"hasOut":false,"names":["all","builder","dev","drvAttrs","drvPath","name","outPath","outputName","outputs","system","type"],"outputName":"dev","pathOut":"/nix/store/3igymyyr87hiw3y11n2jknh5fn06qkz4-x-dev"}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_first_class_values_call_builtin() {
    for source in [
        r#"let
                 f = derivation;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
        r#"let
                 f = builtins.derivation;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
        r#"let
                 d = builtins.derivation {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
        r#"with { derivation = x: x; }; let
                 f = derivation;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
    ] {
        assert_eq!(
            eval_string_bytes(source),
            b"/nix/store/ss8z7hsjimnxam6mx6z8znm64qrk08cn-x",
            "{source}"
        );
    }
}

#[test]
fn derivation_wrapper_is_exposed_as_reference_lambda() {
    let source = r#"let
             inspect = f: {
               args = builtins.functionArgs f;
               isFunction = builtins.isFunction f;
               type = builtins.typeOf f;
             };
           in {
             attr = inspect builtins.derivation;
             global = inspect derivation;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"attr":{"args":{"outputs":true},"isFunction":true,"type":"lambda"},"global":{"args":{"outputs":true},"isFunction":true,"type":"lambda"}}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_rejects_non_list_outputs_like_cpp_wrapper() {
    let error = eval_whnf_owned(&lower(
        r#"derivation {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = "out dev";
               }"#,
    ))
    .expect_err("derivation wrapper maps over outputs as a list");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::String,
            ..
        }
    ));
}

#[test]
fn derivation_strict_supports_custom_outputs() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = [ "out" "dev" ];
             };
           in {
             dev = d.dev;
             devContext = builtins.getContext d.dev;
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             out = d.out;
             outContext = builtins.getContext d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"dev":"/nix/store/phkb0v7mn27i2c5y0qg9d18wvgch5x2w-x-dev","devContext":{"/nix/store/w02nl2gwz0jsij58hzmg7m5f7m8d1404-x.drv":{"outputs":["dev"]}},"drvPath":"/nix/store/w02nl2gwz0jsij58hzmg7m5f7m8d1404-x.drv","names":["dev","drvPath","out"],"out":"/nix/store/kpxa7fq9k2f03c5mn9ipsqjs09lnj1gj-x","outContext":{"/nix/store/w02nl2gwz0jsij58hzmg7m5f7m8d1404-x.drv":{"outputs":["out"]}}}"#.to_vec()
        );
}

#[test]
fn derivation_strict_preserves_raw_outputs_env_string() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = "out  dev";
             };
           in {
             dev = d.dev;
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"dev":"/nix/store/n28wnzwh3wqjmhyz754raw70fhyg436p-x-dev","drvPath":"/nix/store/pgbcwn3hlyzz8y1bzijsdm0faai1bxvz-x.drv","out":"/nix/store/8slxvn562rwfh09l7bjcg4mdpg4lv8vp-x"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_structured_attrs() {
    let source = r#"let
             simple = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               foo = "bar";
             };
             explicitOut = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               outputs = [ "out" ];
             };
             nullValue = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __ignoreNulls = false;
               foo = null;
             };
             jsonKey = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __json = "foo";
               foo = "bar";
             };
           in {
             explicitOutDrv = explicitOut.drvPath;
             explicitOutOut = explicitOut.out;
             jsonKeyDrv = jsonKey.drvPath;
             jsonKeyOut = jsonKey.out;
             nullDrv = nullValue.drvPath;
             nullOut = nullValue.out;
             simpleDrv = simple.drvPath;
             simpleNames = builtins.attrNames simple;
             simpleOut = simple.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"explicitOutDrv":"/nix/store/ni8ck1jwld3qz4fkyb1xfh7kd0qmj5fk-foo.drv","explicitOutOut":"/nix/store/g6x8m6kvfidz7673x8xzkxcjabx4n6dp-foo","jsonKeyDrv":"/nix/store/98yvz8z0i6kzdcsv6zq8cv60dd784yxf-foo.drv","jsonKeyOut":"/nix/store/gw2i989kkschki96vpiz6y779ah7sblw-foo","nullDrv":"/nix/store/rldskjdcwa3p7x5bqy3r217va1jsbjsc-foo.drv","nullOut":"/nix/store/0xghxv8giy66afhkpwbsa2bjhq9j4w8s-foo","simpleDrv":"/nix/store/k6rlb4k10cb9iay283037ml1nv3xma2f-foo.drv","simpleNames":["drvPath","out"],"simpleOut":"/nix/store/6lmv3hyha1g4cb426iwjyifd7nrdv1xn-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_structured_attrs_accepts_reference_constraints() {
    let source = r#"let
             d = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               allowedReferences = [ "out" ];
             };
           in {
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/y83ql5w0pnjb1b5xwaxccgfxigkq51hz-foo.drv","names":["drvPath","out"],"out":"/nix/store/5434vg976sf8rj9ifi8nyil96mcnsgph-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_structured_attrs_observes_builder_context() {
    let source = r#"let
             d = derivationStrict {
               name = "foo";
               system = ":";
               builder = builtins.appendContext ":" {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
               };
               __structuredAttrs = true;
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/1ixzgybyjnapzwa82nb0pm9v2klbzkbw-foo.drv","out":"/nix/store/zxyyy7j9s7c6472nf9klhkhaw43npjlm-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_structured_attrs_requires_string_special_attrs() {
    for source in [
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = 1;
                 __structuredAttrs = true;
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = 1;
                 builder = ":";
                 __structuredAttrs = true;
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputHash = "";
                 outputHashAlgo = true;
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputs = [ 1 ];
               }"#,
    ] {
        let error =
            eval_whnf_owned(&lower(source)).expect_err("structured special attr must be a string");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::Type {
                    expected: "string",
                    ..
                }
            ),
            "{source}: {error:?}"
        );
    }

    for source in [
        r#"derivationStrict {
                 name = "foo";
                 system = builtins.appendContext ":" {
                   "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                 };
                 builder = ":";
                 __structuredAttrs = true;
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputHash = "";
                 outputHashAlgo = builtins.appendContext "sha256" {
                   "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                 };
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputs = [
                   (builtins.appendContext "out" {
                     "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                   })
                 ];
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source))
            .expect_err("structured special attr must not carry context");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::StringContextNotAllowed {
                    op: "derivationStrict",
                    ..
                }
            ),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_outputs_use_cpp_nix_whitespace_set() {
    for source in [
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = builtins.fromJSON "\"out\\fdev\"";
               }"#,
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = builtins.fromJSON "\"out\\u000bdev\"";
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source))
            .expect_err("form feed and vertical tab are not outputs separators");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::DerivationStrict { .. }),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_supports_reference_constraint_attrs() {
    let source = r#"let
             allowed = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               allowedReferences = [ "out" ];
             };
             combined = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               disallowedReferences = [ "out" ];
               allowedRequisites = [ "out" ];
               disallowedRequisites = [ "out" ];
             };
             graph = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               exportReferencesGraph = [ "foo" "bar" ];
             };
             integer = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               allowedReferences = 1;
             };
           in {
             allowedDrv = allowed.drvPath;
             allowedOut = allowed.out;
             combinedDrv = combined.drvPath;
             combinedOut = combined.out;
             graphDrv = graph.drvPath;
             graphOut = graph.out;
             integerDrv = integer.drvPath;
             integerOut = integer.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"allowedDrv":"/nix/store/mpqxk9x7ch6mhlxsl3l50hrfp8plpc2c-foo.drv","allowedOut":"/nix/store/sgc5h0s5r6lx51354xbrcy061qflsch2-foo","combinedDrv":"/nix/store/fbnc7w27pbca6vrmwqlik6a6jv753152-foo.drv","combinedOut":"/nix/store/qksvm54k9gdb59ksf3kc9d91yb7dzq4i-foo","graphDrv":"/nix/store/dfyfp6n0879bzpg67941va1pbby7qc3k-foo.drv","graphOut":"/nix/store/974srlr8l7zk8mqn73nsdq4vniyg3i35-foo","integerDrv":"/nix/store/jqzxf4g629r6d2jj5vl2xpjn5nza5pw9-foo.drv","integerOut":"/nix/store/hy5q2xh2q0lvhbkvww0f0cbywg87a5bk-foo"}"#.to_vec()
        );
}
