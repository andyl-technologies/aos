//! Tests that shadowed builtin names stay ordinary applications.

use super::*;

#[test]
fn shadowed_pure_strict_unary_primops_stay_ordinary_applications() {
    let ir = lowered("typeOf 1");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("length [ 1 ]");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("attrNames { a = 1; }");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("attrValues { a = 1; }");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("tail [ 1 ]");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("functionArgs (x: x)");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("head [ 1 ]");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("ceil 1.2");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("floor 1.8");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("hasContext \"x\"");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("getContext \"x\"");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("parseDrvName \"foo-1\"");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("splitVersion \"1.0\"");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("let typeOf = x: x; in typeOf 1");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::LocalVar);

    let ir = lowered("let isNull = x: false; in isNull null");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::LocalVar);

    let ir = lowered("let builtins = { isInt = x: x; }; in builtins.isInt 1");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("let builtins = { attrNames = x: [ \"local\" ]; }; in builtins.attrNames {}");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir =
        lowered("let builtins = { attrValues = x: [ \"local\" ]; }; in builtins.attrValues {}");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered(
        "let builtins = { getContext = x: { local = true; }; }; in builtins.getContext \"x\"",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered(
        "let builtins = { parseDrvName = x: { name = \"local\"; version = \"\"; }; }; in builtins.parseDrvName \"foo-1\"",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered(
        "let builtins = { splitVersion = x: [ \"local\" ]; }; in builtins.splitVersion \"1.0\"",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir =
        lowered("let builtins = { fromJSON = x: { local = true; }; }; in builtins.fromJSON \"{}\"");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("let builtins = { tail = x: [ \"local\" ]; }; in builtins.tail [ 1 ]");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered(
        "let builtins = { functionArgs = f: { local = true; }; }; in builtins.functionArgs (x: x)",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("let builtins = { head = x: \"local\"; }; in builtins.head [ 1 ]");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("let builtins = { ceil = x: 42; }; in builtins.ceil 1.2");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("let builtins = { floor = x: 42; }; in builtins.floor 1.8");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("let builtins = { hasContext = x: true; }; in builtins.hasContext \"x\"");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("addDrvOutputDependencies \"x\"");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(
        "let builtins = { addDrvOutputDependencies = x: x; }; in builtins.addDrvOutputDependencies \"x\"",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("unsafeDiscardOutputDependency \"x\"");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(
        "let builtins = { unsafeDiscardOutputDependency = x: x; }; in builtins.unsafeDiscardOutputDependency \"x\"",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("unsafeDiscardStringContext \"x\"");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(
        "let builtins = { unsafeDiscardStringContext = x: x; }; in builtins.unsafeDiscardStringContext \"x\"",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("listToAttrs []");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(
        "let builtins = { listToAttrs = list: { local = true; }; }; in builtins.listToAttrs []",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered(
        "let builtins = { concatLists = lists: [ false ]; }; in builtins.concatLists [[true]]",
    );
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("concatLists []");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("let builtins = { length = x: 42; }; in builtins.length [ 1 ]");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("removeAttrs { a = 1; } [ \"a\" ]");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(
        "let builtins = { removeAttrs = set: names: { local = true; }; }; in builtins.removeAttrs {} []",
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

    let ir = lowered("intersectAttrs { a = 1; } { a = 2; }");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(
        "let builtins = { intersectAttrs = left: right: { local = true; }; }; in builtins.intersectAttrs {} {}",
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

    let ir = lowered("catAttrs \"a\" []");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(
        "let builtins = { catAttrs = name: list: [ true ]; }; in builtins.catAttrs \"a\" []",
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

    let ir = lowered("elem 1 []");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("let builtins = { elem = value: list: false; }; in builtins.elem 1 []");
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

    let ir = lowered("lessThan 1 2");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("let builtins = { lessThan = left: right: false; }; in builtins.lessThan 1 2");
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

    let ir = lowered("hashString \"sha256\" \"abc\"");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(
        "let builtins = { hashString = type: value: \"local\"; }; in builtins.hashString \"sha256\" \"abc\"",
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

    let ir = lowered("concatStringsSep \",\" [ \"a\" \"b\" ]");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(
        "let builtins = { concatStringsSep = sep: list: \"local\"; }; in builtins.concatStringsSep \",\" [ \"a\" \"b\" ]",
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

    let ir = lowered("toJSON 1");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("let toJSON = x: \"local\"; in toJSON 1");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::LocalVar);

    let ir = lowered("let builtins = { toJSON = x: \"local\"; }; in builtins.toJSON 1");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let convert_hash_args = "{ hash = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; hashAlgo = \"sha256\"; toHashFormat = \"base64\"; }";
    let ir = lowered(&format!("convertHash {convert_hash_args}"));
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered(&format!(
        "let convertHash = args: \"local\"; in convertHash {convert_hash_args}"
    ));
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::LocalVar);

    let ir = lowered(&format!(
        "let builtins = {{ convertHash = args: \"local\"; }}; in builtins.convertHash {convert_hash_args}"
    ));
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);

    let ir = lowered("toString 1");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("let toString = x: \"local\"; in toString 1");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::LocalVar);

    let ir = lowered("let builtins = { toString = x: \"local\"; }; in builtins.toString 1");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);
}

#[test]
fn shadowed_pure_strict_binary_primops_stay_ordinary_applications() {
    let ir = lowered("elemAt [ 1 ] 0");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("let elemAt = xs: n: 42; in elemAt [ 1 ] 0");
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

    let ir = lowered("let hashString = type: value: \"local\"; in hashString \"sha256\" \"abc\"");
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

    let ir = lowered("let builtins = { elemAt = xs: n: 42; }; in builtins.elemAt [ 1 ] 0");
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

    let ir = lowered("builtins.elemAt [ 1 ]");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::BuiltinAttr);

    let ir = lowered("(builtins.elemAt or (xs: n: 42)) [ 1 ] 0");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);

    let ir = lowered("getAttr \"a\" { a = 1; }");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, first).data else {
        panic!("inner apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

    let ir = lowered("let builtins = { getAttr = name: set: 42; }; in builtins.getAttr \"a\" {}");
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

    let ir = lowered("builtins.hasAttr \"a\"");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::BuiltinAttr);

    for (name, left, right) in [
        ("add", "1", "2"),
        ("sub", "1", "2"),
        ("mul", "1", "2"),
        ("div", "1", "2"),
        ("bitAnd", "1", "2"),
        ("bitOr", "1", "2"),
        ("bitXor", "1", "2"),
        ("all", "(x: true)", "[ 1 ]"),
        ("any", "(x: false)", "[ 1 ]"),
        ("filter", "(x: true)", "[ 1 ]"),
        ("partition", "(x: true)", "[ 1 ]"),
        ("concatMap", "(x: [ x ])", "[ 1 ]"),
        ("groupBy", "(x: \"k\")", "[ 1 ]"),
        ("compareVersions", "\"1.0\"", "\"1.1\""),
    ] {
        let ir = lowered(&format!("{name} {left} {right}"));
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::Apply);
        let IrData::Pair { first, .. } = root.data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Apply);
        let IrData::Pair { first, .. } = node(&ir, first).data else {
            panic!("inner apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::GlobalVar);

        let ir = lowered(&format!(
            "let builtins = {{ {name} = left: right: false; }}; in builtins.{name} {left} {right}"
        ));
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
}
