//! Parser coverage for list element boundaries and adjacent syntax.

use super::*;

#[test]
fn list_elements_do_not_consume_application_chains() {
    let ast = parse("[ 1 2 3 ]");
    let root = node(&ast, ast.root);
    let NodeData::Children(elements) = root.data else {
        panic!("list children expected");
    };
    assert_eq!(ast.arena.child_slice(elements).expect("elements").len(), 3);

    let ast = parse("[ f 1 2 ]");
    let root = node(&ast, ast.root);
    let NodeData::Children(elements) = root.data else {
        panic!("list children expected");
    };
    assert_eq!(ast.arena.child_slice(elements).expect("elements").len(), 3);

    let ast = parse("[ (f 1) 2 ]");
    let root = node(&ast, ast.root);
    let NodeData::Children(elements) = root.data else {
        panic!("list children expected");
    };
    let elements = ast.arena.child_slice(elements).expect("elements");
    assert_eq!(elements.len(), 2);
    assert_eq!(node(&ast, elements[0]).kind, NodeKind::Apply);
}

#[test]
fn rejects_unparenthesized_full_expressions_in_lists() {
    for source in [
        "[ 1 + 2 ]",
        "[ f ? a ]",
        "[ ! f ]",
        "[ x: x ]",
        "[ if true then 1 else 2 ]",
    ] {
        parse_str(source).expect_err("list expression must be parenthesized");
    }

    let ast = parse("[ (1 + 2) ]");
    let root = node(&ast, ast.root);
    let NodeData::Children(elements) = root.data else {
        panic!("list children expected");
    };
    let elements = ast.arena.child_slice(elements).expect("elements");
    assert_eq!(elements.len(), 1);
    assert_eq!(node(&ast, elements[0]).kind, NodeKind::BinOp);
}

#[test]
fn rejects_standalone_dynamic_interpolation() {
    let error = parse_str("${1}").expect_err("standalone interpolation is invalid");
    assert!(matches!(
        error.kind(),
        ParseErrorKind::UnexpectedToken {
            found: TokenKind::DollarBrace,
            ..
        }
    ));
}

#[test]
fn rejects_pipe_operators_without_feature_gate() {
    parse_str("x |> f").expect_err("forward pipe is disabled");
    parse_str("f <| x").expect_err("reverse pipe is disabled");
}

#[test]
fn parses_dynamic_attr_path_segments() {
    let ast = parse("pkg.${name}");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Select);
    let NodeData::Select { path, .. } = root.data else {
        panic!("select data expected");
    };
    let path = ast.arena.child_slice(path).expect("path");
    assert_eq!(path.len(), 1);
    assert_eq!(node(&ast, path[0]).kind, NodeKind::Interp);
}
