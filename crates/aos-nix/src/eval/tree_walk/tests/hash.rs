//! Tree-walk evaluator tests: hash.

use super::*;

#[test]
fn hash_string_primop_hashes_bytes() {
    assert_eq!(
        eval_string_bytes("builtins.hashString \"md5\" \"abc\""),
        b"900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        eval_string_bytes("builtins.hashString \"sha1\" \"abc\""),
        b"a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        eval_string_bytes("builtins.hashString \"sha256\" \"abc\""),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
            eval_string_bytes("builtins.hashString \"sha512\" \"abc\""),
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { hashString = type: value: \"local\"; }; in builtins.hashString \"sha256\" \"abc\""
        ),
        b"local"
    );
}

#[test]
fn first_class_binary_builtin_selects_are_curried() {
    assert_eq!(
        eval_string_bytes("let h = builtins.hashString \"sha256\"; in h \"abc\""),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(eval("let add = builtins.add 1; in add 2").as_int(), Ok(3));
    assert_eq!(
        eval("let less = builtins.lessThan 1; in less 2").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let cmp = builtins.compareVersions \"1.2\"; in cmp \"1.10\"").as_int(),
        Ok(-1)
    );
    assert_eq!(
        eval_string_bytes("let get = builtins.getAttr \"a\"; in get { a = \"x\"; }"),
        b"x"
    );
    assert_eq!(
        eval("let has = builtins.hasAttr \"a\"; in has { a = 1; }").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(
            "let remove = builtins.removeAttrs { a = 1; b = 2; }; in remove [ \"a\" ] == { b = 2; }"
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
            eval("let intersect = builtins.intersectAttrs { a = 0; c = 0; }; in intersect { a = 1; b = 2; } == { a = 1; }").as_bool(),
            Ok(true)
        );
    assert_eq!(
        eval_list_ints(
            "let cat = builtins.catAttrs \"a\"; in cat [ { a = 1; } { b = 2; } { a = 3; } ]"
        ),
        vec![1, 3]
    );
    assert_eq!(
        eval_string_bytes("let join = builtins.concatStringsSep \",\"; in join [ \"a\" \"b\" ]"),
        b"a,b"
    );
    assert_eq!(
        eval("let s = builtins.seq (1 / 0); in builtins.isFunction s").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let s = builtins.seq 1; in builtins.length (s [ 1 (1 / 0) ])").as_int(),
        Ok(2)
    );
}

#[test]
fn first_class_binary_builtin_type_checks_left_before_right() {
    for (source, expected, actual) in [
        (
            "let cmp = builtins.compareVersions 1; in cmp (1 / 0)",
            "string",
            ValueTag::Int,
        ),
        (
            "let and = builtins.bitAnd true; in and (1 / 0)",
            "int",
            ValueTag::Bool,
        ),
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("left argument is rejected");

        let TreeWalkErrorKind::Type {
            expected: found_expected,
            actual: found_actual,
            ..
        } = error.kind()
        else {
            panic!("expected a type error for {source}, got {error:?}");
        };
        assert_eq!(found_expected, expected, "{source}");
        assert_eq!(found_actual, actual, "{source}");
    }
}

#[test]
fn first_class_ternary_builtin_selects_are_curried() {
    assert_eq!(
        eval("let fold = builtins.foldl' builtins.add; sum = fold 0; in sum [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval_string_bytes("let slice = builtins.substring 1; take2 = slice 2; in take2 \"abcd\""),
        b"bc"
    );
    assert_eq!(
        eval_string_bytes(
            "let replace = builtins.replaceStrings [ \"a\" ]; swap = replace [ \"b\" ]; in swap \"a\""
        ),
        b"b"
    );
}

#[test]
fn hash_string_primop_hashes_context_bearing_string_bytes() {
    let ir = lower("builtins.hashString \"sha256\" \"abc\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"abc".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_hash_string_primop_with_string_value(
            ir.root,
            root.span,
            algorithm,
            string,
            string_span,
            value,
        )
        .expect("hashString evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result is a string");

    assert_eq!(
        string.bytes(),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(!string.has_context());
}

#[test]
fn hash_string_primop_rejects_context_bearing_algorithm() {
    let ir = lower("builtins.hashString \"sha256\" (1 / 0)");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"sha256".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing algorithm allocates");

    let error = evaluator
        .eval_hash_algorithm(algorithm, algorithm_span, value, "hashString")
        .expect_err("hashString rejects algorithm string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: algorithm,
            op: "hashString",
        }
    );
    assert_eq!(error.span(), algorithm_span);
}

#[test]
fn hash_string_primop_checks_algorithm_before_string() {
    let ir = lower("builtins.hashString \"bad\" (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("unknown algorithm is rejected first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"bad".to_vec(),
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let ir = lower("builtins.hashString \"SHA256\" \"abc\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];

    let error = eval_whnf_owned(&ir).expect_err("algorithm names are case-sensitive");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"SHA256".to_vec(),
        }
    );
}

#[test]
fn hash_string_primop_type_checks_arguments() {
    let ir = lower("builtins.hashString 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("algorithm must be a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: algorithm,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let ir = lower("builtins.hashString \"sha256\" { outPath = \"abc\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string exists").span;

    let error = eval_whnf_owned(&ir).expect_err("string argument is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: string,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), string_span);
}

#[test]
fn convert_hash_primop_converts_formats() {
    let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base64\"; }}"
        )),
        b"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"nix32\"; }}"
        )),
        b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base32\"; }}"
        )),
        b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"sri\"; }}"
        )),
        b"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"sha256:{sha256}\"; toHashFormat = \"base16\"; }}"
        )),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = builtins.hashString \"md5\" \"abc\"; hashAlgo = \"md5\"; toHashFormat = \"nix32\"; }"
        ),
        b"3jgzhjhz9zjvbb0kyj7jc500ch"
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = builtins.hashString \"sha1\" \"abc\"; hashAlgo = \"sha1\"; toHashFormat = \"base64\"; }"
        ),
        b"qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
    );
    assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = builtins.hashString \"sha512\" \"abc\"; hashAlgo = \"sha512\"; toHashFormat = \"nix32\"; }"
            ),
            b"2gs8k559z4rlahfx0y688s49m2vvszylcikrfinm30ly9rak69236nkam5ydvly1ai7xac99vxfc4ii84hawjbk876blyk1jfhkbbyx"
        );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { convertHash = args: \"local\"; }; in builtins.convertHash { hash = 1 / 0; }"
        ),
        b"local"
    );
}

#[test]
fn convert_hash_primop_can_be_selected_as_a_function() {
    assert_eq!(
        eval_string_bytes(
            "let convert = builtins.convertHash; in convert { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn convert_hash_primop_checks_arguments_in_nix_order() {
    let ir = lower("builtins.convertHash 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("argument must be an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = 1 / 0; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
    ))
    .expect_err("hash is forced first");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
    ))
    .expect_err("hashAlgo is forced second");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = 1 / 0; }",
    ))
    .expect_err("toHashFormat is forced third");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn convert_hash_primop_reports_missing_attributes() {
    let ir = lower("builtins.convertHash { hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("convertHash requires hash");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing hash attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(evaluator.symbols.resolve(symbol), Some(b"hash".as_slice()));

    let ir = lower(
        "builtins.convertHash { hash = builtins.hashString \"sha256\" \"abc\"; hashAlgo = \"sha256\"; }",
    );
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("convertHash requires toHashFormat");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing toHashFormat attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(
        evaluator.symbols.resolve(symbol),
        Some(b"toHashFormat".as_slice())
    );
}

#[test]
fn convert_hash_primop_requires_direct_strings() {
    let ir = lower(
        "builtins.convertHash { hash = { outPath = \"abc\"; }; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
    );
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("hash is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = null; toHashFormat = \"base16\"; }",
    ))
    .expect_err("hashAlgo must be a string when present");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = { outPath = \"base16\"; }; }",
        ))
        .expect_err("toHashFormat is not coerced");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Attrs,
            ..
        }
    ));
}

#[test]
fn convert_hash_primop_rejects_invalid_hashes() {
    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"bad\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("unknown algorithm is rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm { algorithm, .. }
            if algorithm.as_slice() == b"bad"
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"bad\"; }",
    ))
    .expect_err("unknown format is rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashFormat { format, .. }
            if format.as_slice() == b"bad"
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("untyped hashes require hashAlgo");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashAlgorithmRequired { hash, .. }
            if hash.as_slice() == b"abc"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"md5\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("typed hashes must agree with hashAlgo");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashAlgorithmMismatch { expected, .. }
            if expected.as_slice() == b"md5"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("short hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashWrongLength { hash, algorithm, .. }
            if hash.as_slice() == b"abc" && algorithm.as_slice() == b"sha256"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid hex hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidBase16Hash { .. }
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"????????????????????????????????????????????\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid base64 hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidBase64Hash { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"sha256-invalid\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("invalid SRI hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidSriHash { .. }
    ));
}

#[test]
fn placeholder_primop_matches_cpp_nix_hash_scheme() {
    assert_eq!(
        eval_string_bytes(r#"builtins.placeholder "out""#),
        b"/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.placeholder "dev""#),
        b"/02qcpld1y6xhs5gz9bchpxaw0xdhmsp5dv88lh25r2ss44kh8dxz"
    );
    assert_eq!(
        eval("builtins.stringLength (builtins.placeholder \"out\")").as_int(),
        Ok(53)
    );
    assert_eq!(
        eval_string_bytes(r#"let p = builtins.placeholder; in p "out""#),
        b"/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9"
    );
    assert_eq!(
        eval_string_bytes(
            r#"let builtins = { placeholder = output: "local"; }; in builtins.placeholder "out""#
        ),
        b"local"
    );
}
