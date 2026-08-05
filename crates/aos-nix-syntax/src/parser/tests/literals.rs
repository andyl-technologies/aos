//! Parser tests for strings, path literals, and interpolation fragments.

use super::*;
use crate::LexErrorKind;

#[test]
fn parses_string_interpolation_fragments() {
    let ast = parse("\"a${x}b\"");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Interp);
    let NodeData::Children(fragments) = root.data else {
        panic!("interpolation fragments expected");
    };
    assert_eq!(
        ast.arena.child_slice(fragments).expect("fragments").len(),
        3
    );
}

#[test]
fn path_interpolation_requires_a_path_prefix() {
    let ast = parse("./a/${x}/b");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Interp);
    let NodeData::Children(fragments) = root.data else {
        panic!("path interpolation fragments expected");
    };
    let fragments = child_ids(&ast, fragments);
    assert_eq!(fragments.len(), 3);
    assert_eq!(node(&ast, fragments[0]).kind, NodeKind::Path);
    assert_eq!(node(&ast, fragments[1]).kind, NodeKind::Interp);
    assert_eq!(node(&ast, fragments[2]).kind, NodeKind::Path);
    assert_eq!(string_bytes(&ast, fragments[0]), b"./a/");
    assert_eq!(string_bytes(&ast, fragments[2]), b"/b");

    let ast = parse("./a.${foo}/b");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Interp);
    let NodeData::Children(fragments) = root.data else {
        panic!("path interpolation fragments expected");
    };
    let fragments = child_ids(&ast, fragments);
    assert_eq!(fragments.len(), 3);
    assert_eq!(node(&ast, fragments[0]).kind, NodeKind::Path);
    assert_eq!(node(&ast, fragments[1]).kind, NodeKind::Interp);
    assert_eq!(node(&ast, fragments[2]).kind, NodeKind::Path);
    assert_eq!(string_bytes(&ast, fragments[0]), b"./a.");
    assert_eq!(string_bytes(&ast, fragments[2]), b"/b");

    let ast = parse("a.${foo}/b");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Apply);
    let NodeData::Pair { first, second } = root.data else {
        panic!("application payload expected");
    };
    assert_eq!(node(&ast, first).kind, NodeKind::Select);
    assert_eq!(node(&ast, second).kind, NodeKind::Path);

    let ast = parse("a.${foo} / b");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::BinOp);
    let NodeData::Binary { op, lhs, rhs } = root.data else {
        panic!("division payload expected");
    };
    assert_eq!(op, BinOpKind::Div);
    assert_eq!(node(&ast, lhs).kind, NodeKind::Select);
    assert_eq!(node(&ast, rhs).kind, NodeKind::Ident);
}

#[test]
fn dot_slash_dot_is_path_but_dot_slash_is_syntax_error() {
    let ast = parse("./.");
    assert_eq!(node(&ast, ast.root).kind, NodeKind::Path);
    assert_eq!(string_bytes(&ast, ast.root), b"./.");

    let error = parse_str("./").expect_err("bare ./ is not a path expression");
    assert_eq!(error.span(), Span::new(0, 1));
    assert!(matches!(
        error.kind(),
        ParseErrorKind::UnexpectedToken {
            found: TokenKind::Dot,
            ..
        }
    ));
}

#[test]
fn path_literals_reject_trailing_slash() {
    for source in ["./foo/", "foo/bar/", "/tmp/", "./a/${x}/"] {
        let error = parse_str(source).expect_err("bare trailing slash is rejected");
        assert!(matches!(error.kind(), ParseErrorKind::PathTrailingSlash));
    }

    let ast = parse("./foo/.");
    assert_eq!(node(&ast, ast.root).kind, NodeKind::Path);
    assert_eq!(string_bytes(&ast, ast.root), b"./foo/.");

    let ast = parse("./foo/..");
    assert_eq!(node(&ast, ast.root).kind, NodeKind::Path);
    assert_eq!(string_bytes(&ast, ast.root), b"./foo/..");

    let ast = parse("./a/${x}/.");
    assert_eq!(node(&ast, ast.root).kind, NodeKind::Interp);
}

#[test]
fn slash_whitespace_disambiguates_division_from_paths() {
    let ast = parse("1/2");
    assert_eq!(node(&ast, ast.root).kind, NodeKind::Path);
    assert_eq!(string_bytes(&ast, ast.root), b"1/2");

    for source in ["1/ 2", "1 / 2", "1\t/\t2", "1\n/\n2"] {
        let ast = parse(source);
        let root = node(&ast, ast.root);
        let NodeData::Binary { op, .. } = root.data else {
            panic!("division payload expected for {source:?}");
        };
        assert_eq!(root.kind, NodeKind::BinOp);
        assert_eq!(op, BinOpKind::Div);
    }

    let ast = parse("1 /2");
    let root = node(&ast, ast.root);
    let NodeData::Pair { first, second } = root.data else {
        panic!("application payload expected");
    };
    assert_eq!(root.kind, NodeKind::Apply);
    assert_eq!(node(&ast, first).kind, NodeKind::Int);
    assert_eq!(node(&ast, second).kind, NodeKind::Path);
    assert_eq!(string_bytes(&ast, second), b"/2");
}

#[test]
fn home_slash_requires_path_segment() {
    let ast = parse("~/foo");
    assert_eq!(node(&ast, ast.root).kind, NodeKind::Path);
    assert_eq!(string_bytes(&ast, ast.root), b"~/foo");

    let error = parse_str("~/").expect_err("bare ~/ is not a path expression");
    assert!(matches!(
        error.kind(),
        ParseErrorKind::Lex(LexErrorKind::UnexpectedByte(b'~'))
    ));
}

#[test]
fn double_quoted_strings_decode_escape_forms() {
    let ast = parse("\"\\n\\r\\t\\\\\\\"\\${ $${\"");
    assert_eq!(string_bytes(&ast, ast.root), b"\n\r\t\\\"${ $${");

    let ast = parse("\"\\x\\ \\$\\a\"");
    assert_eq!(string_bytes(&ast, ast.root), b"x $a");
}

#[test]
fn double_quoted_strings_preserve_raw_bytes() {
    let ast = parse_bytes(b"\"raw-\xff-byte\"").expect("string bytes parse");
    assert_eq!(string_bytes(&ast, ast.root), b"raw-\xff-byte");
}

#[test]
fn double_quoted_strings_handle_dollar_runs_like_pinned_nix() {
    let ast = parse("\"$${\"");
    assert_eq!(string_bytes(&ast, ast.root), b"$${");

    let ast = parse("\"$$${x}\"");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Interp);
    let NodeData::Children(fragments) = root.data else {
        panic!("interpolation fragments expected");
    };
    let fragments = child_ids(&ast, fragments);
    assert_eq!(fragments.len(), 2);
    assert_eq!(string_bytes(&ast, fragments[0]), b"$$");
    let interpolation = node(&ast, fragments[1]);
    assert_eq!(interpolation.kind, NodeKind::Interp);
    let NodeData::Node(expr) = interpolation.data else {
        panic!("interpolation expression expected");
    };
    assert_eq!(node(&ast, expr).kind, NodeKind::Ident);
    assert_eq!(string_bytes(&ast, expr), b"x");

    let ast = parse("\"$$$${\"");
    assert_eq!(string_bytes(&ast, ast.root), b"$$$${");

    parse_str("\"$$${\"").expect_err("third dollar opens an unterminated interpolation");
}

#[test]
fn double_quoted_strings_normalize_literal_crlf() {
    let ast = parse("\"a\nb\"");
    assert_eq!(string_bytes(&ast, ast.root), b"a\nb");

    let ast = parse("\"a\rb\r\nc\"");
    assert_eq!(string_bytes(&ast, ast.root), b"a\nb\nc");
}

#[test]
fn indented_strings_strip_common_spaces_and_opening_newline() {
    let ast = parse("''\n  one\n    two\n  ''");
    assert_eq!(string_bytes(&ast, ast.root), b"one\n  two\n");

    let ast = parse("''  \n  one\n  ''");
    assert_eq!(string_bytes(&ast, ast.root), b"one\n");

    let ast = parse("''x\n  y\n''");
    assert_eq!(string_bytes(&ast, ast.root), b"x\n  y\n");
}

#[test]
fn indented_strings_ignore_empty_lines_and_keep_tabs() {
    let ast = parse("''\n  one\n\n  \tmake\n  ''");
    assert_eq!(string_bytes(&ast, ast.root), b"one\n\n\tmake\n");

    let ast = parse("''\n    one\n  \n    two\n    ''");
    assert_eq!(string_bytes(&ast, ast.root), b"one\n\ntwo\n");

    let ast = parse("''\n  one\n\t\n  two\n  ''");
    assert_eq!(string_bytes(&ast, ast.root), b"  one\n\t\n  two\n");
}

#[test]
fn indented_strings_decode_escape_forms() {
    let ast = parse("''''$ ''' ''\\n ''\\r ''\\t ''\\x ''${ $${''");
    assert_eq!(string_bytes(&ast, ast.root), b"$ '' \n \r \t x ${ $${");

    let ast = parse(r"''''\${PORT}''");
    assert_eq!(string_bytes(&ast, ast.root), b"${PORT}");

    let ast = parse("''$$$${''");
    assert_eq!(string_bytes(&ast, ast.root), b"$$$${");

    let ast = parse("''$$${x}''");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Interp);
    let NodeData::Children(fragments) = root.data else {
        panic!("interpolation fragments expected");
    };
    let fragments = child_ids(&ast, fragments);
    assert_eq!(fragments.len(), 2);
    assert_eq!(string_bytes(&ast, fragments[0]), b"$$");
    let interpolation = node(&ast, fragments[1]);
    assert_eq!(interpolation.kind, NodeKind::Interp);
    let NodeData::Node(expr) = interpolation.data else {
        panic!("interpolation expression expected");
    };
    assert_eq!(node(&ast, expr).kind, NodeKind::Ident);
    assert_eq!(string_bytes(&ast, expr), b"x");

    parse_str("''$$${''").expect_err("odd dollar run opens interpolation");
}

#[test]
fn indented_strings_handle_trailing_lines_like_pinned_nix() {
    let ast = parse("''\n  one\n    tail''");
    assert_eq!(string_bytes(&ast, ast.root), b"one\n  tail");

    let ast = parse("''\n    one\n  tail''");
    assert_eq!(string_bytes(&ast, ast.root), b"  one\ntail");

    let ast = parse("''\n  one\n    ''");
    assert_eq!(string_bytes(&ast, ast.root), b"one\n");
}

#[test]
fn indented_strings_treat_escaped_newline_as_indent_content() {
    let ast = parse("''\n  ''\\n\n    text\n  ''");
    assert_eq!(string_bytes(&ast, ast.root), b"\n\n  text\n");
}

#[test]
fn indented_string_interpolation_at_line_start_counts_as_content() {
    let ast = parse("''\n  ${x}\n  text\n''");
    let root = node(&ast, ast.root);
    let NodeData::Children(fragments) = root.data else {
        panic!("interpolation fragments expected");
    };
    let fragments = ast.arena.child_slice(fragments).expect("fragments");
    assert_eq!(fragments.len(), 2);
    assert_eq!(node(&ast, fragments[0]).kind, NodeKind::Interp);
    assert_eq!(string_bytes(&ast, fragments[1]), b"\ntext\n");
}

#[test]
fn indented_string_deindent_preserves_interpolation_source_span() {
    let source = "''\n    ${missing}\n    text\n  ''";
    let ast = parse(source);
    let root = node(&ast, ast.root);
    let NodeData::Children(fragments) = root.data else {
        panic!("interpolation fragments expected");
    };
    let fragments = ast.arena.child_slice(fragments).expect("fragments");

    let interpolation = node(&ast, fragments[0]);
    assert_eq!(interpolation.kind, NodeKind::Interp);
    assert_eq!(span_text(source, interpolation.span), "${missing}");
}
