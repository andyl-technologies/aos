//! Unit tests for the Nix parser: grammar coverage, precedence, string
//! decoding, and binding normalization.

use std::{
    fs,
    path::{Path, PathBuf},
};

use super::*;

mod list_syntax;
mod literals;

const SOURCE_SEED_PREFIX: &str = "# aos-nix-fuzz-source\n";

fn parse(source: &str) -> ParsedAst {
    parse_str(source).expect("source parses")
}

fn span_text<'a>(source: &'a str, span: Span) -> &'a str {
    &source[span.start as usize..span.end as usize]
}

fn parse_acceptance(source: &str) -> Result<(), String> {
    parse_str(source)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn rnix_acceptance(source: &str) -> Result<(), String> {
    let parsed = rnix::parse(source);
    let errors = parsed.errors();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; "))
    }
}

fn assert_rnix_acceptance_matches(source: &str) {
    assert_rnix_acceptance_matches_named(source, source);
}

fn assert_rnix_acceptance_matches_named(name: &str, source: &str) {
    let aos = parse_acceptance(source);
    let rnix = rnix_acceptance(source);
    assert_eq!(
        aos.is_ok(),
        rnix.is_ok(),
        "parser acceptance diverged for {name}:\n{source}\n\
         aos-nix: {aos:?}\nrnix: {rnix:?}"
    );
}

#[derive(Debug)]
struct ParserOracleCase {
    name: String,
    source: String,
}

fn local_parser_oracle_cases() -> Vec<ParserOracleCase> {
    let root = workspace_root();
    let mut cases = Vec::new();
    collect_nix_fixture_cases(
        &root.join("crates/aos-nix/tests/fixtures/lang"),
        &root,
        &mut cases,
    );
    collect_source_seed_cases(&root.join("fuzz/corpus"), &root, &mut cases);
    cases.sort_by(|left, right| left.name.cmp(&right.name));
    cases
}

fn workspace_parser_oracle_cases() -> Vec<ParserOracleCase> {
    let root = workspace_root();
    let mut cases = Vec::new();
    collect_workspace_nix_source_cases(&root, &root, &mut cases);
    cases.sort_by(|left, right| left.name.cmp(&right.name));
    cases
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("aos-nix-syntax crate lives under workspace/crates")
        .to_path_buf()
}

fn collect_nix_fixture_cases(dir: &Path, root: &Path, cases: &mut Vec<ParserOracleCase>) {
    for path in recursively_list_files(dir) {
        if path.extension().and_then(|extension| extension.to_str()) != Some("nix") {
            continue;
        }
        cases.push(ParserOracleCase {
            name: relative_display(root, &path),
            source: fs::read_to_string(&path).expect("Nix fixture is UTF-8"),
        });
    }
}

fn collect_source_seed_cases(dir: &Path, root: &Path, cases: &mut Vec<ParserOracleCase>) {
    for path in recursively_list_files(dir) {
        if path.extension().and_then(|extension| extension.to_str()) != Some("seed") {
            continue;
        }
        let seed = fs::read_to_string(&path).expect("fuzz seed is UTF-8");
        let Some(source) = seed.strip_prefix(SOURCE_SEED_PREFIX) else {
            continue;
        };
        cases.push(ParserOracleCase {
            name: relative_display(root, &path),
            source: source.trim().to_owned(),
        });
    }
}

fn collect_workspace_nix_source_cases(dir: &Path, root: &Path, cases: &mut Vec<ParserOracleCase>) {
    for entry in fs::read_dir(dir).expect("workspace source directory exists") {
        let entry = entry.expect("workspace source entry is readable");
        let path = entry.path();
        let file_type = entry
            .file_type()
            .expect("workspace source file type is readable");
        if file_type.is_dir() {
            if workspace_oracle_skips_dir(&path) {
                continue;
            }
            collect_workspace_nix_source_cases(&path, root, cases);
        } else if file_type.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("nix")
        {
            cases.push(ParserOracleCase {
                name: relative_display(root, &path),
                source: fs::read_to_string(&path).expect("workspace Nix source is UTF-8"),
            });
        }
    }
}

fn workspace_oracle_skips_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(name, ".git" | ".direnv" | "result" | "target") || name.starts_with("result-")
}

fn recursively_list_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files(dir, &mut files);
    files.sort();
    files
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("oracle corpus directory exists") {
        let entry = entry.expect("oracle corpus entry is readable");
        let path = entry.path();
        let file_type = entry
            .file_type()
            .expect("oracle corpus file type is readable");
        if file_type.is_dir() {
            collect_files(&path, files);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn node(ast: &ParsedAst, id: NodeId) -> &super::super::Node {
    ast.arena.node(id).expect("node exists")
}

fn string_bytes(ast: &ParsedAst, id: NodeId) -> &[u8] {
    let NodeData::Symbol(symbol) = node(ast, id).data else {
        panic!("string node should carry a symbol");
    };
    ast.symbols.resolve(symbol).expect("string symbol resolves")
}

fn child_ids(ast: &ParsedAst, slice: ChildSlice) -> &[NodeId] {
    ast.arena.child_slice(slice).expect("child slice exists")
}

fn binding_path_and_value(ast: &ParsedAst, binding: NodeId) -> (&[NodeId], NodeId) {
    let NodeData::Binding { path, value } = node(ast, binding).data else {
        panic!("binding payload expected");
    };
    (child_ids(ast, path), value)
}

fn binding_name<'a>(ast: &'a ParsedAst, binding: NodeId) -> &'a [u8] {
    let (path, _) = binding_path_and_value(ast, binding);
    assert_eq!(path.len(), 1);
    static_attr_name(ast, path[0])
}

fn binary(ast: &ParsedAst, id: NodeId) -> (BinOpKind, NodeId, NodeId) {
    let NodeData::Binary { op, lhs, rhs } = node(ast, id).data else {
        panic!("binary payload expected");
    };
    (op, lhs, rhs)
}

fn static_attr_name(ast: &ParsedAst, segment: NodeId) -> &[u8] {
    let segment = node(ast, segment);
    match segment.kind {
        NodeKind::Ident | NodeKind::Str => {
            let NodeData::Symbol(symbol) = segment.data else {
                panic!("static segment should carry a symbol");
            };
            ast.symbols.resolve(symbol).expect("symbol resolves")
        }
        NodeKind::Interp => {
            let NodeData::Node(child) = segment.data else {
                panic!("static interpolation should carry an expression");
            };
            static_attr_name(ast, child)
        }
        _ => panic!("binding path should carry a static name"),
    }
}

#[test]
fn parses_let_lambda_application_skeleton() {
    let ast = parse("let x = 1; f = y: x + y; in f 41");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::LetIn);

    let NodeData::LetIn { bindings, body } = root.data else {
        panic!("root should carry let-in data");
    };
    assert_eq!(ast.arena.child_slice(bindings).expect("bindings").len(), 2);
    assert_eq!(node(&ast, body).kind, NodeKind::Apply);
}

#[test]
fn parser_can_thread_shared_symbol_table_across_files() {
    let first = parse("alpha");
    let second = parse_str_with_symbols("beta", first.symbols).expect("second source parses");

    assert_eq!(
        second.symbols.resolve(Symbol::new(0)),
        Some(b"alpha".as_slice())
    );
    assert_eq!(
        second.symbols.resolve(Symbol::new(1)),
        Some(b"beta".as_slice())
    );

    let NodeData::Symbol(symbol) = node(&second, second.root).data else {
        panic!("root should be an identifier symbol");
    };
    assert_eq!(symbol.as_u32(), 1);

    let third = parse_str_with_symbols("alpha", second.symbols).expect("third source parses");
    let NodeData::Symbol(symbol) = node(&third, third.root).data else {
        panic!("root should be an identifier symbol");
    };
    assert_eq!(symbol.as_u32(), 0);

    let isolated = parse("beta");
    assert_eq!(
        isolated.symbols.resolve(Symbol::new(0)),
        Some(b"beta".as_slice())
    );
}

#[test]
fn parses_legacy_let_attrset_as_rec_attrset_body_select() {
    let ast = parse("let { x = 1; body = x + 1; }");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Select);

    let NodeData::Select {
        receiver,
        path,
        default,
    } = root.data
    else {
        panic!("legacy let attrset should lower to body selection data");
    };
    assert!(default.is_none());
    assert_eq!(node(&ast, receiver).kind, NodeKind::RecAttrSet);
    let NodeData::Children(bindings) = node(&ast, receiver).data else {
        panic!("legacy let attrset receiver should carry bindings");
    };
    assert_eq!(child_ids(&ast, bindings).len(), 2);
    let [body] = child_ids(&ast, path) else {
        panic!("legacy let selection path should contain only body");
    };
    assert_eq!(node(&ast, *body).kind, NodeKind::Ident);
    let NodeData::Symbol(symbol) = node(&ast, *body).data else {
        panic!("legacy let selection path should use the body identifier");
    };
    assert_eq!(ast.symbols.resolve(symbol), Some(b"body".as_slice()));
}

#[test]
fn parser_acceptance_matches_rnix_oracle_on_p1_syntax_corpus() {
    for source in [
        "1",
        "let x = 1; y = 2; in x + y",
        "let { x = 1; body = x + 1; }",
        "rec { x = 1; y = x; }",
        "{ inherit (rec { x = 1; }) x; nested.value = 2; }",
        "{ ${\"dynamic\"} = 1; plain = 2; }",
        "({ a = 1; }).a or 2",
        "pkg ? meta.name",
        "with { x = 1; }; x",
        "assert true; 1",
        "if true then [ 1 \"two\" ] else []",
        "({ x, y ? 2, ... }@args: x + y) { x = 1; }",
        "args@{ x, y ? 2, ... }: x",
        "''\n  hello ${\"world\"}\n''",
    ] {
        assert_rnix_acceptance_matches(source);
    }

    for source in [
        "let x = ; in x",
        "if true then 1",
        "{ a = 1; ",
        "with; 1",
        "assert; 1",
        "(1",
        "[ 1 2",
        "x:",
        "{ x, x }: x",
    ] {
        assert_rnix_acceptance_matches(source);
    }
}

#[test]
fn parser_acceptance_matches_rnix_oracle_on_local_fixtures_and_fuzz_seeds() {
    let cases = local_parser_oracle_cases();
    assert!(
        cases.len() >= 30,
        "expected local fixtures plus source seeds, got {} cases",
        cases.len()
    );
    assert!(
        cases
            .iter()
            .any(|case| case.name.starts_with("crates/aos-nix/tests/fixtures/lang/")),
        "expected local lang fixtures in rnix oracle corpus"
    );
    assert!(
        cases
            .iter()
            .any(|case| case.name.starts_with("fuzz/corpus/internal_diff_raw/")),
        "expected internal-diff source-seed fuzz cases in rnix oracle corpus"
    );
    assert!(
        cases
            .iter()
            .any(|case| case.name.starts_with("fuzz/corpus/parity_json/")),
        "expected parity-json source-seed fuzz cases in rnix oracle corpus"
    );

    for case in cases {
        assert_rnix_acceptance_matches_named(&case.name, &case.source);
    }
}

#[test]
fn parser_acceptance_matches_rnix_oracle_on_workspace_nix_sources() {
    let cases = workspace_parser_oracle_cases();
    assert!(
        cases.len() >= 600,
        "expected real workspace Nix source corpus, got {} cases",
        cases.len()
    );
    assert!(
        cases.iter().any(|case| case.name == "pkgs/default.nix"),
        "expected package-set root in workspace parser corpus"
    );
    assert!(
        cases
            .iter()
            .any(|case| case.name == "pkgs/toolchain/cmake.nix"),
        "expected toolchain package source in workspace parser corpus"
    );
    assert!(
        cases.iter().any(|case| case.name == "modules/default.nix"),
        "expected module root in workspace parser corpus"
    );
    assert!(
        cases
            .iter()
            .any(|case| case.name == "modules/systemd/system.nix"),
        "expected systemd module source in workspace parser corpus"
    );
    assert!(
        cases.iter().any(|case| case.name == "systems/server.nix"),
        "expected system root in workspace parser corpus"
    );

    for case in cases {
        assert_rnix_acceptance_matches_named(&case.name, &case.source);
    }
}

#[test]
fn workspace_parser_oracle_skips_generated_directories() {
    let root = workspace_root();

    for skipped in [".git", ".direnv", "result", "result-system", "target"] {
        assert!(
            workspace_oracle_skips_dir(&root.join(skipped)),
            "expected workspace parser oracle to skip {skipped}"
        );
    }
    assert!(
        !workspace_oracle_skips_dir(&root.join("pkgs")),
        "expected package sources to stay in the workspace parser oracle"
    );
}

#[test]
fn pratt_parser_honors_multiplicative_precedence() {
    let ast = parse("1 + 2 * 3");
    let root = node(&ast, ast.root);
    let NodeData::Binary { op, rhs, .. } = root.data else {
        panic!("root should be binary");
    };
    assert_eq!(op, BinOpKind::Add);
    assert_eq!(node(&ast, rhs).kind, NodeKind::BinOp);
    let NodeData::Binary { op: rhs_op, .. } = node(&ast, rhs).data else {
        panic!("rhs should be binary");
    };
    assert_eq!(rhs_op, BinOpKind::Mul);
}

#[test]
fn pratt_parser_matches_nix_operator_precedence_and_associativity() {
    let ast = parse("f x.y");
    let root = node(&ast, ast.root);
    let NodeData::Pair { second, .. } = root.data else {
        panic!("application payload expected");
    };
    assert_eq!(root.kind, NodeKind::Apply);
    assert_eq!(node(&ast, second).kind, NodeKind::Select);

    let ast = parse("f a b");
    let root = node(&ast, ast.root);
    let NodeData::Pair { first, .. } = root.data else {
        panic!("application payload expected");
    };
    assert_eq!(root.kind, NodeKind::Apply);
    assert_eq!(node(&ast, first).kind, NodeKind::Apply);

    let ast = parse("- -x");
    let root = node(&ast, ast.root);
    let NodeData::Unary { op, operand } = root.data else {
        panic!("unary payload expected");
    };
    assert_eq!(op, UnaryOpKind::Neg);
    assert_eq!(node(&ast, operand).kind, NodeKind::UnaryOp);

    let ast = parse("! a == b");
    let (op, lhs, _) = binary(&ast, ast.root);
    assert_eq!(op, BinOpKind::Eq);
    assert_eq!(node(&ast, lhs).kind, NodeKind::UnaryOp);

    let ast = parse("a ++ b ++ c");
    let (op, _, rhs) = binary(&ast, ast.root);
    assert_eq!(op, BinOpKind::Concat);
    assert_eq!(binary(&ast, rhs).0, BinOpKind::Concat);

    let ast = parse("a * b / c");
    let (op, lhs, _) = binary(&ast, ast.root);
    assert_eq!(op, BinOpKind::Div);
    assert_eq!(binary(&ast, lhs).0, BinOpKind::Mul);

    let ast = parse("a + b - c");
    let (op, lhs, _) = binary(&ast, ast.root);
    assert_eq!(op, BinOpKind::Sub);
    assert_eq!(binary(&ast, lhs).0, BinOpKind::Add);

    let ast = parse("a // b // c");
    let (op, _, rhs) = binary(&ast, ast.root);
    assert_eq!(op, BinOpKind::Update);
    assert_eq!(binary(&ast, rhs).0, BinOpKind::Update);

    let ast = parse("a && b && c");
    let (op, lhs, _) = binary(&ast, ast.root);
    assert_eq!(op, BinOpKind::And);
    assert_eq!(binary(&ast, lhs).0, BinOpKind::And);

    let ast = parse("a || b || c");
    let (op, lhs, _) = binary(&ast, ast.root);
    assert_eq!(op, BinOpKind::Or);
    assert_eq!(binary(&ast, lhs).0, BinOpKind::Or);

    let ast = parse("a -> b -> c");
    let (op, _, rhs) = binary(&ast, ast.root);
    assert_eq!(op, BinOpKind::Impl);
    assert_eq!(binary(&ast, rhs).0, BinOpKind::Impl);
}

#[test]
fn rejects_non_associative_equality_chains() {
    for (source, operator) in [
        ("a == b == c", "=="),
        ("a != b != c", "!="),
        ("a < b < c", "<"),
        ("a <= b <= c", "<="),
        ("a > b > c", ">"),
        ("a >= b >= c", ">="),
        ("s ? a ? b", "?"),
    ] {
        let error = parse_str(source).expect_err("operator chaining is rejected");
        assert_eq!(
            error.kind(),
            &ParseErrorKind::NonAssociativeOperator { operator }
        );
    }
}

#[test]
fn reports_first_significant_error_after_skipped_trivia() {
    let source = "let x = 1;\n  @@@\nin x";
    let error = parse_str(source).expect_err("invalid binding errors");
    let start = source.find('@').expect("source contains bad token") as u32;
    assert_eq!(error.span(), Span::new(start, start + 1));
    assert!(matches!(
        error.kind(),
        ParseErrorKind::UnexpectedToken {
            found: TokenKind::At,
            ..
        }
    ));
}

#[test]
fn parses_select_defaults_and_has_attr_paths() {
    let ast = parse("pkg.meta.name or fallback");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Select);
    let NodeData::Select { path, default, .. } = root.data else {
        panic!("select data expected");
    };
    assert!(default.is_some());
    assert_eq!(ast.arena.child_slice(path).expect("path").len(), 2);

    let ast = parse("pkg ? meta.name");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::HasAttr);
}

#[test]
fn contextual_or_matches_pinned_keyword_positions() {
    parse("({ or = 1; }).or");
    parse("({ missing = 1; }).or or 2");
    parse("let or = 1; in 0");
    parse("let inherit ({ or = 1; }) or; in 0");
    parse("let f = x: x; or = 2; in f or");
    parse("let f = x: x; or = { a = 1; }; in f or ? a");

    for source in [
        "or",
        "(or)",
        "[ or ]",
        "if or then 1 else 0",
        "assert or; 1",
        "or: 1",
        "or@{ a }: 1",
        "{ a }@or: 1",
        "{ or }: 1",
        "{ or ? 1 }: 1",
        "let f = x: x; or = { a = 1; }; in f or.a",
        "let f = x: x; or = { a = 1; }; in f or or 2",
    ] {
        parse_str(source).expect_err("contextual or position should match pinned Nix");
    }
}

#[test]
fn parse_fail_lexical_rejections_are_reported() {
    for source in [
        "\"unterminated",
        "''unterminated",
        "/* unterminated",
        "*/",
        "999999999999999999999999",
    ] {
        parse_str(source).expect_err("malformed lexical input should be rejected");
    }
}

#[test]
fn semicolon_is_not_a_general_expression_terminator() {
    parse("let x = 1; in x");
    parse("{ x = 1; }");
    parse("assert true; 1");
    parse("with { x = 1; }; x");

    for source in ["1;", "[ 1; ]", "(1;)"] {
        parse_str(source).expect_err("semicolon is not a general expression terminator");
    }
}

#[test]
fn select_defaults_bind_tighter_than_application_and_operators() {
    let ast = parse("({ a = 10; }).a or 1 * 2");
    let root = node(&ast, ast.root);
    let NodeData::Binary { op, lhs, .. } = root.data else {
        panic!("root should be binary");
    };
    assert_eq!(op, BinOpKind::Mul);
    assert_eq!(node(&ast, lhs).kind, NodeKind::Select);

    let ast = parse("f.a or g 1");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Apply);
    let NodeData::Pair { first, .. } = root.data else {
        panic!("apply pair expected");
    };
    assert_eq!(node(&ast, first).kind, NodeKind::Select);
}

#[test]
fn has_attr_binds_tighter_than_boolean_and() {
    let ast = parse("{ a = 1; } ? a && b");
    let root = node(&ast, ast.root);
    let NodeData::Binary { op, lhs, .. } = root.data else {
        panic!("root should be binary");
    };
    assert_eq!(op, BinOpKind::And);
    assert_eq!(node(&ast, lhs).kind, NodeKind::HasAttr);

    let ast = parse("false && { a = 1; } ? a");
    let root = node(&ast, ast.root);
    let NodeData::Binary { op, rhs, .. } = root.data else {
        panic!("root should be binary");
    };
    assert_eq!(op, BinOpKind::And);
    assert_eq!(node(&ast, rhs).kind, NodeKind::HasAttr);
}

#[test]
fn parses_formal_lambda_with_bounded_lookahead() {
    let ast = parse("{ a, b ? 1, ... }@args: a");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::Lambda);
    let NodeData::Pair { first, .. } = root.data else {
        panic!("lambda pair expected");
    };
    assert_eq!(node(&ast, first).kind, NodeKind::FormalSet);
    let NodeData::FormalSet {
        formals,
        ellipsis,
        alias,
    } = node(&ast, first).data
    else {
        panic!("formal set data expected");
    };
    assert!(ellipsis);
    assert!(alias.is_some());
    assert_eq!(ast.arena.child_slice(formals).expect("formals").len(), 2);
}

#[test]
fn formal_lookahead_handles_interpolated_defaults() {
    parse("{ a ? \"${x}\" }: a");
    parse("{ a ? ./x/${name} }: a");
}

#[test]
fn rejects_invalid_formal_patterns() {
    for source in ["{ ..., a }: a", "{ a, ..., b }: a", "args@{}@more: args"] {
        let error = parse_str(source).expect_err("invalid formal pattern");
        assert!(matches!(
            error.kind(),
            ParseErrorKind::InvalidFormalPattern { .. } | ParseErrorKind::UnexpectedToken { .. }
        ));
    }

    for source in [
        "{ ..., }: 1",
        "{ a, ..., }: a",
        "{ a, a }: a",
        "args@{ args }: args",
        "{ args } @ args: args",
    ] {
        let error = parse_str(source).expect_err("invalid formal pattern");
        assert!(matches!(
            error.kind(),
            ParseErrorKind::InvalidFormalPattern { .. } | ParseErrorKind::UnexpectedToken { .. }
        ));
    }
}

#[test]
fn parses_attrsets_lists_and_inherit() {
    let ast = parse("{ inherit (src) name version; list = [ 1 2 3 ]; }");
    let root = node(&ast, ast.root);
    assert_eq!(root.kind, NodeKind::AttrSet);
    let NodeData::Children(bindings) = root.data else {
        panic!("attrset children expected");
    };
    let bindings = ast.arena.child_slice(bindings).expect("bindings");
    assert_eq!(bindings.len(), 3);
    assert_eq!(node(&ast, bindings[0]).kind, NodeKind::Binding);
    assert_eq!(node(&ast, bindings[1]).kind, NodeKind::Binding);
    assert_eq!(node(&ast, bindings[2]).kind, NodeKind::Binding);
    assert_eq!(binding_name(&ast, bindings[0]), b"name");
    assert_eq!(binding_name(&ast, bindings[1]), b"version");
    assert_eq!(binding_name(&ast, bindings[2]), b"list");

    let (_, value) = binding_path_and_value(&ast, bindings[0]);
    assert_eq!(node(&ast, value).kind, NodeKind::Inherit);
}

#[test]
fn empty_inherit_groups_desugar_to_no_bindings() {
    let ast = parse("{ inherit; x = 1; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 1);
    assert_eq!(binding_name(&ast, bindings[0]), b"x");
}

#[test]
fn empty_inherit_from_groups_keep_a_scope_marker() {
    let ast = parse("{ inherit (src); x = 1; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 2);
    assert_eq!(node(&ast, bindings[0]).kind, NodeKind::Inherit);
    assert_eq!(binding_name(&ast, bindings[1]), b"x");
}

#[test]
fn inherit_from_bindings_share_the_source_expression() {
    let ast = parse("{ inherit (src) name version; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 2);

    let (_, first_value) = binding_path_and_value(&ast, bindings[0]);
    let (_, second_value) = binding_path_and_value(&ast, bindings[1]);
    let NodeData::Inherit {
        from: Some(first_from),
        ..
    } = node(&ast, first_value).data
    else {
        panic!("first inherit marker expected");
    };
    let NodeData::Inherit {
        from: Some(second_from),
        ..
    } = node(&ast, second_value).data
    else {
        panic!("second inherit marker expected");
    };
    assert_eq!(first_from, second_from);
}

#[test]
fn merges_static_attr_path_bindings_into_nested_attrsets() {
    let ast = parse("{ a.b = 1; a.c = 2; }");
    let root = node(&ast, ast.root);
    let NodeData::Children(bindings) = root.data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 1);
    assert_eq!(binding_name(&ast, bindings[0]), b"a");

    let (_, nested) = binding_path_and_value(&ast, bindings[0]);
    assert_eq!(node(&ast, nested).kind, NodeKind::AttrSet);
    let NodeData::Children(nested_bindings) = node(&ast, nested).data else {
        panic!("nested attrset children expected");
    };
    let nested_bindings = child_ids(&ast, nested_bindings);
    assert_eq!(nested_bindings.len(), 2);
    assert_eq!(binding_name(&ast, nested_bindings[0]), b"b");
    assert_eq!(binding_name(&ast, nested_bindings[1]), b"c");

    let ast = parse("{ a = { b = 1; }; a.c = 2; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 1);
    assert_eq!(binding_name(&ast, bindings[0]), b"a");

    let ast = parse("{ a.b = 1; a = { c = 2; }; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 1);
    assert_eq!(binding_name(&ast, bindings[0]), b"a");
}

#[test]
fn attr_path_bindings_normalize_let_bindings_too() {
    let ast = parse("let a.b = 1; a.c = 2; in a");
    let NodeData::LetIn { bindings, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 1);
    assert_eq!(binding_name(&ast, bindings[0]), b"a");

    let ast = parse("let ${\"a\"}.b = 1; a.c = 2; in a");
    let NodeData::LetIn { bindings, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 1);
    assert_eq!(binding_name(&ast, bindings[0]), b"a");
}

#[test]
fn attr_path_merging_uses_static_string_names() {
    let ast = parse("{ \"a\".b = 1; a.c = 2; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 1);
    assert_eq!(binding_name(&ast, bindings[0]), b"a");

    let ast = parse("{ ${\"a\"}.b = 1; a.c = 2; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 1);
    assert_eq!(binding_name(&ast, bindings[0]), b"a");
}

#[test]
fn dynamic_first_attr_paths_are_not_statically_merged() {
    let ast = parse("{ ${name}.b = 1; a.c = 2; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 2);

    let ast = parse("{ ${\"a\" + \"b\"}.c = 1; ab.d = 2; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let bindings = child_ids(&ast, bindings);
    assert_eq!(bindings.len(), 2);
}

#[test]
fn duplicate_static_attr_paths_are_parse_errors() {
    for source in [
        "{ a = 1; a = 2; }",
        "{ a.b = 1; a.b = 2; }",
        "{ a = 1; a.b = 2; }",
        "{ a = { b = 1; }; a.b = 2; }",
        "{ a.b = 1; a = { b = 2; }; }",
        "let x = 1; in { inherit x; x = 2; }",
        "let x = 1; in { inherit x; inherit x; }",
        "let x = 1; in { a = { inherit x; }; a.x = 2; }",
        "let inherit x; x = 1; in x",
        "let inherit (src) x; x = 1; in x",
    ] {
        let error = parse_str(source).expect_err("duplicate attr path errors");
        assert!(matches!(
            error.kind(),
            ParseErrorKind::DuplicateAttribute { .. }
        ));
    }
}

#[test]
fn duplicate_attr_errors_keep_desugared_original_binding_spans() {
    for (source, first_text, second_text) in [
        ("{ a.b = 1; a.b = 2; }", "a.b = 1;", "a.b = 2;"),
        ("{ a = { b = 1; }; a.b = 2; }", "b = 1;", "a.b = 2;"),
        ("{ a.b = 1; a = { b = 2; }; }", "a.b = 1;", "b = 2;"),
        (
            "let x = 1; in { inherit x; x = 2; }",
            "inherit x;",
            "x = 2;",
        ),
        (
            "let src = { x = 1; }; in { inherit (src) x; x = 2; }",
            "inherit (src) x;",
            "x = 2;",
        ),
        (
            "let x = 1; in { inherit x; inherit   x; }",
            "inherit x;",
            "inherit   x;",
        ),
    ] {
        let error = parse_str(source).expect_err("duplicate attr path errors");
        let ParseErrorKind::DuplicateAttribute { first, second } = error.kind() else {
            panic!("duplicate attr path error expected for {source}");
        };

        assert!(first.start < second.start, "{source}");
        assert_eq!(span_text(source, *first), first_text, "{source}");
        assert_eq!(span_text(source, *second), second_text, "{source}");
        assert_eq!(error.span(), *second, "{source}");
        assert_eq!(span_text(source, error.span()), second_text, "{source}");
    }
}

#[test]
fn attr_path_merging_preserves_first_attrset_recursiveness() {
    let ast = parse("{ a = rec { c = c; }; a.b = 1; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let (_, value) = binding_path_and_value(&ast, child_ids(&ast, bindings)[0]);
    assert_eq!(node(&ast, value).kind, NodeKind::RecAttrSet);

    let ast = parse("{ a.b = 1; a = rec { c = c; }; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset children expected");
    };
    let (_, value) = binding_path_and_value(&ast, child_ids(&ast, bindings)[0]);
    assert_eq!(node(&ast, value).kind, NodeKind::AttrSet);
}
