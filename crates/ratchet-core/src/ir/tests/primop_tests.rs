//! Tests for direct primop and builtin lowering.

use super::*;

#[test]
fn lowers_effectful_unary_primops_directly() {
    for (source, name) in [
        ("import ./foo.nix", b"import".as_slice()),
        ("builtins.readFile ./foo.txt", b"readFile".as_slice()),
        ("builtins.readDir ./foo", b"readDir".as_slice()),
        ("builtins.pathExists ./foo", b"pathExists".as_slice()),
        ("builtins.path { path = ./foo; }", b"path".as_slice()),
        (
            "builtins.fetchurl \"file:///tmp/aos-fetchurl-test\"",
            b"fetchurl".as_slice(),
        ),
        (r#"builtins.getFlake "nixpkgs""#, b"getFlake".as_slice()),
        ("builtins.readFileType ./foo", b"readFileType".as_slice()),
        ("builtins.getEnv \"HOME\"", b"getEnv".as_slice()),
        (
            "builtins.derivation { name = \"x\"; system = \"x86_64-linux\"; builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder\"; }",
            b"derivation".as_slice(),
        ),
    ] {
        let ir = lowered_nix(source);
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::PrimOp);
        assert_eq!(root.effect, TEST_NIX_EFFECTFUL);
        let IrData::PrimOp { symbol, args } = root.data else {
            panic!("primop payload expected");
        };
        assert_eq!(symbol_text(&ir, symbol), name);
        let args = ir.arena.child_slice(args).expect("primop args exist");
        assert_eq!(args.len(), 1);
        assert_ne!(node(&ir, args[0]).kind, IrKind::ThunkAlloc);
    }
}

#[test]
fn default_core_lowering_does_not_own_nix_builtin_effects() {
    let ir = lowered("builtins.readFile ./foo.txt");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::PrimOp);
    assert_eq!(root.effect, EffectClass::pure());
    assert!(root.effect.is_speculable());
}

#[test]
fn bare_derivation_stays_wrapper_application() {
    let ir = lowered(
        "derivation { name = \"x\"; system = \"x86_64-linux\"; builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder\"; }",
    );
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("application payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);
}

#[test]
fn effectful_unary_primop_arguments_are_strict() {
    let ir = lowered("builtins.getEnv (let x = \"HOME\"; in x)");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::PrimOp);
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("primop payload expected");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    assert_eq!(args.len(), 1);
    assert_eq!(node(&ir, args[0]).kind, IrKind::Let);
}

#[test]
fn lowers_pure_strict_unary_primops_directly() {
    for (source, name) in [
        ("builtins.isAttrs {}", b"isAttrs".as_slice()),
        ("builtins.isList [ 1 ]", b"isList".as_slice()),
        ("builtins.isFunction (x: x)", b"isFunction".as_slice()),
        ("builtins.isString \"x\"", b"isString".as_slice()),
        ("builtins.isInt 1", b"isInt".as_slice()),
        ("builtins.isFloat 1.0", b"isFloat".as_slice()),
        ("builtins.isBool true", b"isBool".as_slice()),
        ("builtins.isNull null", b"isNull".as_slice()),
        ("isNull null", b"isNull".as_slice()),
        ("builtins.isPath \"not-path\"", b"isPath".as_slice()),
        ("builtins.typeOf null", b"typeOf".as_slice()),
        ("builtins.length [ 1 2 ]", b"length".as_slice()),
        ("builtins.attrNames { a = 1; }", b"attrNames".as_slice()),
        ("builtins.attrValues { a = 1; }", b"attrValues".as_slice()),
        ("builtins.tail [ 1 2 ]", b"tail".as_slice()),
        ("builtins.functionArgs (x: x)", b"functionArgs".as_slice()),
        ("builtins.head [ 1 ]", b"head".as_slice()),
        ("builtins.ceil 1.2", b"ceil".as_slice()),
        ("builtins.floor 1.8", b"floor".as_slice()),
        ("builtins.hasContext \"x\"", b"hasContext".as_slice()),
        ("builtins.getContext \"x\"", b"getContext".as_slice()),
        (
            "builtins.addDrvOutputDependencies \"x\"",
            b"addDrvOutputDependencies".as_slice(),
        ),
        (
            "builtins.unsafeDiscardOutputDependency \"abc\"",
            b"unsafeDiscardOutputDependency".as_slice(),
        ),
        (
            "builtins.listToAttrs [ { name = \"a\"; value = 1; } ]",
            b"listToAttrs".as_slice(),
        ),
        ("builtins.concatLists [ [ 1 ] ]", b"concatLists".as_slice()),
        ("builtins.stringLength \"abc\"", b"stringLength".as_slice()),
        ("builtins.baseNameOf \"/a/b\"", b"baseNameOf".as_slice()),
        ("builtins.dirOf \"/a/b\"", b"dirOf".as_slice()),
        (
            "builtins.parseDrvName \"foo-1.0\"",
            b"parseDrvName".as_slice(),
        ),
        (
            "builtins.splitVersion \"1.0pre2\"",
            b"splitVersion".as_slice(),
        ),
        (
            "builtins.fromJSON \"{\\\"a\\\":1}\"",
            b"fromJSON".as_slice(),
        ),
        ("builtins.fromTOML \"a = 1\"", b"fromTOML".as_slice()),
        ("builtins.toString 1", b"toString".as_slice()),
        ("builtins.toJSON { a = 1; }", b"toJSON".as_slice()),
        ("builtins.tryEval 1", b"tryEval".as_slice()),
        (
            "builtins.convertHash { hash = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; hashAlgo = \"sha256\"; toHashFormat = \"base64\"; }",
            b"convertHash".as_slice(),
        ),
        (
            "builtins.unsafeDiscardStringContext \"abc\"",
            b"unsafeDiscardStringContext".as_slice(),
        ),
    ] {
        let ir = lowered_nix(source);
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::PrimOp);
        assert_eq!(root.effect, EffectClass::pure());
        let IrData::PrimOp { symbol, args } = root.data else {
            panic!("primop payload expected");
        };
        assert_eq!(symbol_text(&ir, symbol), name);
        let args = ir.arena.child_slice(args).expect("primop args exist");
        assert_eq!(args.len(), 1);
        assert_ne!(node(&ir, args[0]).kind, IrKind::ThunkAlloc);
    }
}

#[test]
fn lowers_pure_lazy_unary_primops_directly() {
    let ir = lowered("builtins.break (let x = [ 1 2 ]; in x)");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::PrimOp);
    assert_eq!(root.effect, EffectClass::pure());
    let IrData::PrimOp { symbol, args } = root.data else {
        panic!("primop payload expected");
    };
    assert_eq!(symbol_text(&ir, symbol), b"break");
    let args = ir.arena.child_slice(args).expect("primop args exist");
    assert_eq!(args.len(), 1);
    assert_eq!(node(&ir, args[0]).kind, IrKind::ThunkAlloc);

    let ir = lowered("builtins.break ./foo");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::PrimOp);
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("primop payload expected");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    assert_eq!(args.len(), 1);
    assert_eq!(node(&ir, args[0]).kind, IrKind::ThunkAlloc);
    assert_eq!(node(&ir, thunk_inner(&ir, args[0])).kind, IrKind::Path);
}

#[test]
fn lowers_pure_strict_binary_primops_directly() {
    for (source, name) in [
        (
            "builtins.appendContext \"x\" {}",
            b"appendContext".as_slice(),
        ),
        ("builtins.elemAt [ 1 ] 0", b"elemAt".as_slice()),
        ("builtins.getAttr \"a\" { a = 1; }", b"getAttr".as_slice()),
        ("builtins.hasAttr \"a\" { a = 1; }", b"hasAttr".as_slice()),
        (
            "builtins.removeAttrs { a = 1; } [ \"a\" ]",
            b"removeAttrs".as_slice(),
        ),
        (
            "builtins.intersectAttrs { a = 1; } { a = 2; }",
            b"intersectAttrs".as_slice(),
        ),
        (
            "builtins.catAttrs \"a\" [ { a = 1; } ]",
            b"catAttrs".as_slice(),
        ),
        ("builtins.elem 1 [ 1 ]", b"elem".as_slice()),
        ("builtins.lessThan 1 2", b"lessThan".as_slice()),
        (
            "builtins.hashString \"sha256\" \"abc\"",
            b"hashString".as_slice(),
        ),
        ("builtins.split \"-\" \"a-b\"", b"split".as_slice()),
        (
            "builtins.concatStringsSep \",\" [ \"a\" \"b\" ]",
            b"concatStringsSep".as_slice(),
        ),
        (
            "builtins.mapAttrs (name: value: value) { a = 1; }",
            b"mapAttrs".as_slice(),
        ),
        (
            "builtins.zipAttrsWith (name: values: values) [ { a = 1; } ]",
            b"zipAttrsWith".as_slice(),
        ),
        ("builtins.match \"a\" \"a\"", b"match".as_slice()),
        ("builtins.add 1 2", b"add".as_slice()),
        ("builtins.sub 2 1", b"sub".as_slice()),
        ("builtins.mul 2 3", b"mul".as_slice()),
        ("builtins.div 4 2", b"div".as_slice()),
        ("builtins.bitAnd 6 3", b"bitAnd".as_slice()),
        ("builtins.bitOr 4 1", b"bitOr".as_slice()),
        ("builtins.bitXor 6 3", b"bitXor".as_slice()),
        (
            "builtins.compareVersions \"1.0\" \"1.1\"",
            b"compareVersions".as_slice(),
        ),
        ("builtins.all (x: true) [ 1 ]", b"all".as_slice()),
        ("builtins.any (x: false) [ 1 ]", b"any".as_slice()),
        ("builtins.filter (x: true) [ 1 ]", b"filter".as_slice()),
        ("builtins.genList (x: x) 1", b"genList".as_slice()),
        ("builtins.map (x: x) [ 1 ]", b"map".as_slice()),
        (
            "builtins.partition (x: true) [ 1 ]",
            b"partition".as_slice(),
        ),
        (
            "builtins.concatMap (x: [ x ]) [ 1 ]",
            b"concatMap".as_slice(),
        ),
        ("builtins.groupBy (x: \"k\") [ 1 ]", b"groupBy".as_slice()),
    ] {
        let ir = lowered_nix(source);
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::PrimOp);
        assert_eq!(root.effect, EffectClass::pure());
        let IrData::PrimOp { symbol, args } = root.data else {
            panic!("primop payload expected");
        };
        assert_eq!(symbol_text(&ir, symbol), name);
        let args = ir.arena.child_slice(args).expect("primop args exist");
        assert_eq!(args.len(), 2);
        for arg in args {
            assert_ne!(node(&ir, *arg).kind, IrKind::ThunkAlloc);
        }
    }
}

#[test]
fn lowers_effectful_strict_binary_primops_directly() {
    for (source, name) in [
        (
            "builtins.hashFile \"sha256\" ./crates/Cargo.toml",
            b"hashFile".as_slice(),
        ),
        (
            "builtins.filterSource (path: type: true) ./foo",
            b"filterSource".as_slice(),
        ),
    ] {
        let ir = lowered_nix(source);
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::PrimOp);
        assert_eq!(root.effect, TEST_NIX_EFFECTFUL);
        let IrData::PrimOp { symbol, args } = root.data else {
            panic!("primop payload expected");
        };
        assert_eq!(symbol_text(&ir, symbol), name);
        let args = ir.arena.child_slice(args).expect("primop args exist");
        assert_eq!(args.len(), 2);
        for arg in args {
            assert_ne!(node(&ir, *arg).kind, IrKind::ThunkAlloc);
        }
    }
}

#[test]
fn lowers_pure_strict_lazy_binary_primops_directly() {
    for name in ["deepSeq", "seq"] {
        let source = format!("builtins.{name} (let x = 1; in x) (let y = 2; in y)");
        let ir = lowered_nix(&source);
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::PrimOp);
        assert_eq!(root.effect, EffectClass::pure());
        let IrData::PrimOp { symbol, args } = root.data else {
            panic!("primop payload expected");
        };
        assert_eq!(symbol_text(&ir, symbol), name.as_bytes());
        let args = ir.arena.child_slice(args).expect("primop args exist");
        assert_eq!(args.len(), 2);
        assert_eq!(node(&ir, args[0]).kind, IrKind::Let);
        assert_eq!(node(&ir, args[1]).kind, IrKind::ThunkAlloc);
    }
}

#[test]
fn lowers_effectful_strict_lazy_binary_primops_directly() {
    for name in ["trace", "traceVerbose", "warn"] {
        let source = format!("builtins.{name} (let x = 1; in x) (let y = 2; in y)");
        let ir = lowered_nix(&source);
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::PrimOp);
        assert_eq!(root.effect, TEST_NIX_EFFECTFUL);
        let IrData::PrimOp { symbol, args } = root.data else {
            panic!("primop payload expected");
        };
        assert_eq!(symbol_text(&ir, symbol), name.as_bytes());
        let args = ir.arena.child_slice(args).expect("primop args exist");
        assert_eq!(args.len(), 2);
        assert_eq!(node(&ir, args[0]).kind, IrKind::Let);
        assert_eq!(node(&ir, args[1]).kind, IrKind::ThunkAlloc);
    }
}

#[test]
fn shadowed_pure_strict_lazy_binary_primops_stay_ordinary_applications() {
    for source in [
        "deepSeq 1 2",
        "seq 1 2",
        "let deepSeq = first: second: second; in deepSeq 1 2",
        "let seq = first: second: second; in seq 1 2",
        "let builtins = { deepSeq = first: second: second; }; in builtins.deepSeq 1 2",
        "let builtins = { seq = first: second: second; }; in builtins.seq 1 2",
        "(builtins.deepSeq or (first: second: second)) 1 2",
        "(builtins.seq or (first: second: second)) 1 2",
    ] {
        let ir = lowered(source);
        let root = root_node(&ir);
        let root = if root.kind == IrKind::Let {
            let IrData::Let { body, .. } = root.data else {
                panic!("let payload expected");
            };
            node(&ir, body)
        } else {
            root
        };
        assert_eq!(root.kind, IrKind::Apply);
        let IrData::Pair { first, .. } = root.data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Apply);
    }
}

#[test]
fn shadowed_effectful_strict_lazy_binary_primops_stay_ordinary_applications() {
    for source in [
        "trace 1 2",
        "traceVerbose 1 2",
        "warn 1 2",
        "let trace = first: second: second; in trace 1 2",
        "let traceVerbose = first: second: second; in traceVerbose 1 2",
        "let warn = first: second: second; in warn 1 2",
        "let builtins = { trace = first: second: second; }; in builtins.trace 1 2",
        "let builtins = { traceVerbose = first: second: second; }; in builtins.traceVerbose 1 2",
        "let builtins = { warn = first: second: second; }; in builtins.warn 1 2",
        "(builtins.trace or (first: second: second)) 1 2",
        "(builtins.traceVerbose or (first: second: second)) 1 2",
        "(builtins.warn or (first: second: second)) 1 2",
    ] {
        let ir = lowered(source);
        let root = root_node(&ir);
        let root = if root.kind == IrKind::Let {
            let IrData::Let { body, .. } = root.data else {
                panic!("let payload expected");
            };
            node(&ir, body)
        } else {
            root
        };
        assert_eq!(root.kind, IrKind::Apply);
        let IrData::Pair { first, .. } = root.data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Apply);
    }
}

#[test]
fn lowers_pure_strict_ternary_primops_directly() {
    for (source, name) in [
        ("builtins.substring 1 2 \"abcd\"", b"substring".as_slice()),
        (
            "builtins.foldl' (acc: x: acc) 0 [ 1 ]",
            b"foldl'".as_slice(),
        ),
        (
            "builtins.replaceStrings [ \"a\" ] [ \"b\" ] \"a\"",
            b"replaceStrings".as_slice(),
        ),
    ] {
        let ir = lowered(source);
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::PrimOp);
        assert_eq!(root.effect, EffectClass::pure());
        let IrData::PrimOp { symbol, args } = root.data else {
            panic!("primop payload expected");
        };
        assert_eq!(symbol_text(&ir, symbol), name);
        let args = ir.arena.child_slice(args).expect("primop args exist");
        assert_eq!(args.len(), 3);
        for arg in args {
            assert_ne!(node(&ir, *arg).kind, IrKind::ThunkAlloc);
        }
    }
}

#[test]
fn shadowed_pure_strict_ternary_primops_stay_ordinary_applications() {
    for source in [
        "substring 1 2 \"abcd\"",
        "let substring = start: len: value: \"local\"; in substring 1 2 \"abcd\"",
        "let builtins = { substring = start: len: value: \"local\"; }; in builtins.substring 1 2 \"abcd\"",
        "(builtins.substring or (start: len: value: \"default\")) 1 2 \"abcd\"",
        "foldl' (acc: x: acc) 0 [ 1 ]",
        "let foldl' = op: initial: list: \"local\"; in foldl' (acc: x: acc) 0 [ 1 ]",
        "let builtins = { foldl' = op: initial: list: \"local\"; }; in builtins.foldl' (acc: x: acc) 0 [ 1 ]",
        "(builtins.foldl' or (op: initial: list: \"default\")) (acc: x: acc) 0 [ 1 ]",
        "replaceStrings [ \"a\" ] [ \"b\" ] \"a\"",
        "let replaceStrings = from: to: string: \"local\"; in replaceStrings [ \"a\" ] [ \"b\" ] \"a\"",
        "let builtins = { replaceStrings = from: to: string: \"local\"; }; in builtins.replaceStrings [ \"a\" ] [ \"b\" ] \"a\"",
        "(builtins.replaceStrings or (from: to: string: \"default\")) [ \"a\" ] [ \"b\" ] \"a\"",
    ] {
        let ir = lowered(source);
        let root = root_node(&ir);
        let root = if root.kind == IrKind::Let {
            let IrData::Let { body, .. } = root.data else {
                panic!("let payload expected");
            };
            node(&ir, body)
        } else {
            root
        };
        assert_eq!(root.kind, IrKind::Apply);
        let IrData::Pair { first, .. } = root.data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Apply);
    }
}

#[test]
fn shadowed_effectful_primops_stay_ordinary_applications() {
    let ir = lowered("let import = x: x; in import ./foo.nix");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::LocalVar);

    let ir = lowered("let hashFile = type: path: path; in hashFile \"sha256\" ./foo");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::LocalVar);

    let ir = lowered("let builtins = { readFile = x: x; }; in builtins.readFile ./foo");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered(
        "let builtins = { hashFile = type: path: path; }; in builtins.hashFile \"sha256\" ./foo",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);
}

#[test]
fn effectful_primop_select_defaults_stay_ordinary_applications() {
    let ir = lowered("(builtins.readFile or (x: x)) ./foo");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);
}

#[test]
fn lowers_add_error_context_directly_with_lazy_context_message() {
    let ir = lowered("builtins.addErrorContext (let x = 1; in x) (let y = 2; in y)");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::PrimOp);
    assert_eq!(root.effect, EffectClass::pure());
    let IrData::PrimOp { symbol, args } = root.data else {
        panic!("primop payload expected");
    };
    assert_eq!(symbol_text(&ir, symbol), b"addErrorContext");
    let args = ir.arena.child_slice(args).expect("primop args exist");
    assert_eq!(args.len(), 2);
    assert_eq!(node(&ir, args[0]).kind, IrKind::ThunkAlloc);
    assert_eq!(node(&ir, args[1]).kind, IrKind::Let);
}

#[test]
fn shadowed_add_error_context_stays_ordinary_application() {
    for source in [
        "addErrorContext \"ctx\" 1",
        "let addErrorContext = context: value: value; in addErrorContext \"ctx\" 1",
        "let builtins = { addErrorContext = context: value: value; }; in builtins.addErrorContext \"ctx\" 1",
        "(builtins.addErrorContext or (context: value: value)) \"ctx\" 1",
    ] {
        let ir = lowered(source);
        let root = root_node(&ir);
        let root = if root.kind == IrKind::Let {
            let IrData::Let { body, .. } = root.data else {
                panic!("let payload expected");
            };
            node(&ir, body)
        } else {
            root
        };
        assert_eq!(root.kind, IrKind::Apply);
        let IrData::Pair { first, .. } = root.data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Apply);
    }
}
