//! Unit tests for scope resolution.

use super::*;
use crate::syntax::{BinOpKind, parse_str};

fn resolved(source: &str) -> ResolvedAst {
    resolve(parse_str(source).expect("source parses")).expect("scope resolves")
}

fn node(ast: &ResolvedAst, id: NodeId) -> &Node {
    ast.arena.node(id).expect("node exists")
}

fn child_ids(ast: &ResolvedAst, slice: ChildSlice) -> &[NodeId] {
    ast.arena.child_slice(slice).expect("child slice exists")
}

fn binding_value(ast: &ResolvedAst, binding: NodeId) -> NodeId {
    let NodeData::Binding { value, .. } = node(ast, binding).data else {
        panic!("binding payload expected");
    };
    value
}

fn local_slot(ast: &ResolvedAst, id: NodeId) -> u32 {
    let NodeData::Local { slot } = node(ast, id).data else {
        panic!("local payload expected");
    };
    slot
}

fn upval(ast: &ResolvedAst, id: NodeId) -> (u32, u32) {
    let NodeData::Upval { depth, slot } = node(ast, id).data else {
        panic!("upvalue payload expected");
    };
    (depth, slot)
}

fn inherit_resolution(ast: &ResolvedAst, id: NodeId) -> &InheritResolution {
    let group = ast
        .scopes
        .inherit_for_node(id)
        .expect("inherit group attached");
    ast.scopes
        .inherit_resolution(group)
        .expect("inherit resolution exists")
}

#[test]
fn resolves_let_lambda_to_de_bruijn_slots() {
    let ast = resolved("let x = 1; f = y: x + y; in f 41");
    let root = node(&ast, ast.root);
    let NodeData::LetIn { bindings, body } = root.data else {
        panic!("let-in payload expected");
    };
    let let_frame = ast
        .scopes
        .frame_for_node(ast.root)
        .expect("let frame exists");
    let let_info = &ast.scopes.frames()[let_frame.index()];
    assert_eq!(let_info.slot_count, 2);
    assert!(let_info.rec);

    let apply = node(&ast, body);
    let NodeData::Pair { first: callee, .. } = apply.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ast, callee).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, callee), 1);

    let binding_ids = child_ids(&ast, bindings);
    let lambda = binding_value(&ast, binding_ids[1]);
    let lambda_frame = ast
        .scopes
        .frame_for_node(lambda)
        .expect("lambda frame exists");
    let lambda_info = &ast.scopes.frames()[lambda_frame.index()];
    assert_eq!(lambda_info.slot_count, 1);
    assert_eq!(
        lambda_info.captures.as_ref(),
        &[Upvalue { depth: 1, slot: 0 }]
    );

    let NodeData::Pair {
        second: lambda_body,
        ..
    } = node(&ast, lambda).data
    else {
        panic!("lambda payload expected");
    };
    let NodeData::Binary {
        op,
        lhs: x_ref,
        rhs: y_ref,
    } = node(&ast, lambda_body).data
    else {
        panic!("binary payload expected");
    };
    assert_eq!(op, BinOpKind::Add);
    assert_eq!(node(&ast, x_ref).kind, NodeKind::UpvalVar);
    assert_eq!(upval(&ast, x_ref), (1, 0));
    assert_eq!(node(&ast, y_ref).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, y_ref), 0);
}

#[test]
fn let_frames_are_self_visible() {
    let ast = resolved("let x = y; y = 1; in x");
    let NodeData::LetIn { bindings, body } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let binding_ids = child_ids(&ast, bindings);
    let x_value = binding_value(&ast, binding_ids[0]);
    assert_eq!(node(&ast, x_value).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, x_value), 1);
    assert_eq!(node(&ast, body).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, body), 0);
}

#[test]
fn recursive_attrsets_are_self_visible_but_plain_attrsets_are_not() {
    let ast = resolved("rec { a = 1; b = a; }");
    let root = node(&ast, ast.root);
    let frame = ast
        .scopes
        .frame_for_node(ast.root)
        .expect("rec frame exists");
    assert_eq!(ast.scopes.frames()[frame.index()].slot_count, 2);
    assert!(ast.scopes.frames()[frame.index()].rec);
    let NodeData::Children(bindings) = root.data else {
        panic!("rec attrset payload expected");
    };
    let b_value = binding_value(&ast, child_ids(&ast, bindings)[1]);
    assert_eq!(node(&ast, b_value).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, b_value), 0);

    let ast = resolved("let outer = 9; in { outer = 1; b = outer; }");
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Children(bindings) = node(&ast, body).data else {
        panic!("attrset payload expected");
    };
    let b_value = binding_value(&ast, child_ids(&ast, bindings)[1]);
    assert_eq!(node(&ast, b_value).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, b_value), 0);
}

#[test]
fn attr_path_merges_preserve_order_sensitive_rec_scope() {
    let ast = resolved("{ a = rec { c = c; }; a.b = 1; }");
    let NodeData::Children(bindings) = node(&ast, ast.root).data else {
        panic!("attrset payload expected");
    };
    let a_value = binding_value(&ast, child_ids(&ast, bindings)[0]);
    let NodeData::Children(nested_bindings) = node(&ast, a_value).data else {
        panic!("nested attrset payload expected");
    };
    let c_value = binding_value(&ast, child_ids(&ast, nested_bindings)[0]);
    assert_eq!(node(&ast, c_value).kind, NodeKind::LocalVar);

    let error = resolve(parse_str("{ a.b = 1; a = rec { c = c; }; }").expect("source parses"))
        .expect_err("later rec attrset is merged into the earlier plain prefix");
    assert!(matches!(error.kind(), ScopeErrorKind::UndefinedSymbol(_)));
}

#[test]
fn recursive_dynamic_attr_names_do_not_enter_the_rec_scope() {
    let ast = resolved("let outer = 1; in rec { ${outer} = 2; a = 3; b = a; }");
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Children(bindings) = node(&ast, body).data else {
        panic!("rec attrset payload expected");
    };
    let binding_ids = child_ids(&ast, bindings);
    let NodeData::Binding { path, .. } = node(&ast, binding_ids[0]).data else {
        panic!("binding payload expected");
    };
    let dynamic_segment = child_ids(&ast, path)[0];
    let NodeData::Node(dynamic_name) = node(&ast, dynamic_segment).data else {
        panic!("dynamic attr segment expected");
    };
    assert_eq!(node(&ast, dynamic_name).kind, NodeKind::UpvalVar);
    assert_eq!(upval(&ast, dynamic_name), (1, 0));

    let b_value = binding_value(&ast, binding_ids[2]);
    assert_eq!(node(&ast, b_value).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, b_value), 0);

    let ast = resolved(r#"let a = "outer"; in rec { ${a} = 1; a = "inner"; }"#);
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Children(bindings) = node(&ast, body).data else {
        panic!("rec attrset payload expected");
    };
    let NodeData::Binding { path, .. } = node(&ast, child_ids(&ast, bindings)[0]).data else {
        panic!("binding payload expected");
    };
    let dynamic_segment = child_ids(&ast, path)[0];
    let NodeData::Node(dynamic_name) = node(&ast, dynamic_segment).data else {
        panic!("dynamic attr segment expected");
    };
    assert_eq!(node(&ast, dynamic_name).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, dynamic_name), 0);

    let ast = resolved(r#"let name = "dyn"; dyn = 9; in rec { ${name} = 1; a = dyn; }"#);
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Children(bindings) = node(&ast, body).data else {
        panic!("rec attrset payload expected");
    };
    let a_value = binding_value(&ast, child_ids(&ast, bindings)[1]);
    assert_eq!(node(&ast, a_value).kind, NodeKind::UpvalVar);
    assert_eq!(upval(&ast, a_value), (1, 1));

    let error = resolve(
        parse_str(r#"let name = "dyn"; in rec { ${name} = 1; a = dyn; }"#).expect("source parses"),
    )
    .expect_err("dynamic target does not enter the rec lexical scope");
    assert!(matches!(error.kind(), ScopeErrorKind::UndefinedSymbol(_)));
}

#[test]
fn nested_lambdas_record_transitive_capture_sets() {
    let ast = resolved("let x = 1; in y: z: x + y + z");
    let NodeData::LetIn {
        body: outer_lambda, ..
    } = node(&ast, ast.root).data
    else {
        panic!("let-in payload expected");
    };
    let NodeData::Pair {
        second: inner_lambda,
        ..
    } = node(&ast, outer_lambda).data
    else {
        panic!("outer lambda payload expected");
    };

    let outer_frame = ast
        .scopes
        .frame_for_node(outer_lambda)
        .expect("outer lambda frame exists");
    assert_eq!(
        ast.scopes.frames()[outer_frame.index()].captures.as_ref(),
        &[Upvalue { depth: 1, slot: 0 }]
    );

    let inner_frame = ast
        .scopes
        .frame_for_node(inner_lambda)
        .expect("inner lambda frame exists");
    assert_eq!(
        ast.scopes.frames()[inner_frame.index()].captures.as_ref(),
        &[Upvalue { depth: 1, slot: 0 }, Upvalue { depth: 2, slot: 0 }]
    );
}

#[test]
fn lexical_bindings_beat_active_with_scopes() {
    let ast = resolved("let a = 1; xs = {}; in with xs; a");
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Pair {
        first: scrutinee,
        second: with_body,
    } = node(&ast, body).data
    else {
        panic!("with payload expected");
    };
    assert_eq!(node(&ast, scrutinee).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, scrutinee), 1);
    assert_eq!(node(&ast, with_body).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, with_body), 0);

    let frame = ast
        .scopes
        .frame_for_node(ast.root)
        .expect("let frame exists");
    assert!(ast.scopes.frames()[frame.index()].has_with);
}

#[test]
fn with_variables_record_innermost_first_probe_chains() {
    let ast = resolved("let outer = {}; in with outer; with inner; missing");
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Pair {
        first: outer,
        second: inner_with,
    } = node(&ast, body).data
    else {
        panic!("outer with payload expected");
    };
    let NodeData::Pair {
        first: inner,
        second: missing,
    } = node(&ast, inner_with).data
    else {
        panic!("inner with payload expected");
    };
    assert_eq!(node(&ast, outer).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, outer), 0);
    assert_eq!(node(&ast, inner).kind, NodeKind::WithVar);
    assert_eq!(node(&ast, missing).kind, NodeKind::WithVar);
    let NodeData::WithVar { symbol, .. } = node(&ast, inner).data else {
        panic!("with-var payload expected");
    };
    assert_eq!(ast.symbols.resolve(symbol), Some(b"inner".as_slice()));
    let NodeData::WithVar { chain, .. } = node(&ast, missing).data else {
        panic!("with-var payload expected");
    };
    let chain = ast
        .scopes
        .with_chain(WithChainId::new(chain))
        .expect("with chain exists");
    assert_eq!(chain.scopes.as_ref(), &[inner, outer]);
}

#[test]
fn lambda_parameters_shadow_active_with_scopes() {
    let ast = resolved("let outer = {}; in with outer; (x: x)");
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Pair { second: lambda, .. } = node(&ast, body).data else {
        panic!("with payload expected");
    };
    let NodeData::Pair {
        second: lambda_body,
        ..
    } = node(&ast, lambda).data
    else {
        panic!("lambda payload expected");
    };
    assert_eq!(node(&ast, lambda_body).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, lambda_body), 0);
}

#[test]
fn unshadowable_global_names_shadow_active_with_scopes() {
    for source in [
        "with { true = 1; }; true",
        "with { false = 1; }; false",
        "with { null = 1; }; null",
        "with { builtins = 1; }; builtins",
        "with { map = f: xs: 7; }; map",
        "with { toString = x: \"with\"; }; toString",
        "with { derivationStrict = x: x; }; derivationStrict",
    ] {
        let ast = resolved(source);
        let NodeData::Pair { second, .. } = node(&ast, ast.root).data else {
            panic!("with payload expected");
        };
        assert_eq!(node(&ast, second).kind, NodeKind::GlobalVar, "{source}");
    }
}

#[test]
fn shadowable_builtin_attrs_use_active_with_scopes() {
    for source in [
        "with { currentTime = 123; }; currentTime",
        "with { storeDir = \"with\"; }; storeDir",
        "with { langVersion = 9; }; langVersion",
        "with { length = x: 7; }; length",
        "with { concatMap = f: xs: 7; }; concatMap",
    ] {
        let ast = resolved(source);
        let NodeData::Pair { second, .. } = node(&ast, ast.root).data else {
            panic!("with payload expected");
        };
        assert_eq!(node(&ast, second).kind, NodeKind::WithVar, "{source}");
    }
}

#[test]
fn global_names_are_classified_separately_from_undefined_names() {
    let ast = resolved("true");
    assert_eq!(node(&ast, ast.root).kind, NodeKind::GlobalVar);

    let ast = resolved("foldl'");
    assert_eq!(node(&ast, ast.root).kind, NodeKind::GlobalVar);

    for name in [
        "toLower",
        "toUpper",
        "toTOML",
        "concatStrings",
        "stringToCharacters",
        "splitString",
        "hasPrefix",
        "hasSuffix",
        "optionalString",
        "removePrefix",
        "removeSuffix",
        "escapeShellArg",
        "versionAtLeast",
        "versionOlder",
        "foldr",
        "foldl",
        "reverse",
        "range",
        "remove",
        "zipWith",
        "flatten",
        "unique",
        "last",
        "init",
        "take",
        "drop",
        "count",
        "imap0",
        "forEach",
        "optionals",
        "mapAttrsToList",
        "filterAttrs",
        "recursiveUpdate",
        "attrByPath",
        "optionalAttrs",
        "mapAttrs'",
        "genAttrs",
        "nameValuePair",
        "id",
        "const",
        "flip",
        "composeManyExtensions",
        "pipe",
        "fix",
        "makeExtensible",
        "importJSON",
        "importTOML",
    ] {
        let error =
            resolve(parse_str(name).expect("source parses")).expect_err("name is not global");
        assert!(
            matches!(error.kind(), ScopeErrorKind::UndefinedSymbol(_)),
            "{name} should not be classified as a global builtin",
        );
    }

    let error =
        resolve(parse_str("missing").expect("source parses")).expect_err("missing name errors");
    assert!(matches!(error.kind(), ScopeErrorKind::UndefinedSymbol(_)));
}

#[test]
fn bare_inherit_sources_resolve_outside_the_self_frame() {
    let ast = resolved("let z = 0; x = 1; y = let inherit x; in x; in y");
    let NodeData::LetIn {
        bindings: outer_bindings,
        ..
    } = node(&ast, ast.root).data
    else {
        panic!("outer let-in payload expected");
    };
    let y_value = binding_value(&ast, child_ids(&ast, outer_bindings)[2]);
    let NodeData::LetIn {
        bindings: inner_bindings,
        body: inner_body,
    } = node(&ast, y_value).data
    else {
        panic!("inner let-in payload expected");
    };
    let inherit = child_ids(&ast, inner_bindings)[0];
    let resolution = inherit_resolution(&ast, inherit);
    assert_eq!(resolution.sources.len(), 1);
    let source = resolution.sources[0].source;
    assert_eq!(node(&ast, source).kind, NodeKind::UpvalVar);
    assert_eq!(upval(&ast, source), (1, 1));
    assert_eq!(node(&ast, inner_body).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, inner_body), 0);
}

#[test]
fn inherit_from_expression_records_resolved_select_sources() {
    let ast = resolved("let src = { name = 1; version = 2; }; in { inherit (src) name version; }");
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Children(bindings) = node(&ast, body).data else {
        panic!("attrset payload expected");
    };
    let binding_ids = child_ids(&ast, bindings);
    let resolution = inherit_resolution(&ast, binding_ids[0]);
    let second_resolution = inherit_resolution(&ast, binding_ids[1]);
    let from = resolution.from.expect("inherit source expression exists");
    assert_eq!(second_resolution.from, Some(from));
    assert_eq!(node(&ast, from).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, from), 0);
    let source = resolution.sources[0].source;
    assert_eq!(node(&ast, source).kind, NodeKind::Select);
    let NodeData::Select { receiver, path, .. } = node(&ast, source).data else {
        panic!("select payload expected");
    };
    assert_eq!(receiver, from);
    assert_eq!(child_ids(&ast, path).len(), 1);
}

#[test]
fn inherit_from_expression_in_let_sees_the_self_frame() {
    let ast = resolved("let inherit (src) name; src = { name = 1; }; in name");
    let NodeData::LetIn { bindings, body } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let binding_ids = child_ids(&ast, bindings);
    let resolution = inherit_resolution(&ast, binding_ids[0]);
    let from = resolution.from.expect("inherit source expression exists");
    assert_eq!(node(&ast, from).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, from), 1);
    assert_eq!(node(&ast, body).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, body), 0);
}

#[test]
fn empty_inherit_from_groups_still_scope_check_the_source() {
    let error = resolve(parse_str("{ inherit (missing); x = 1; }").expect("source parses"))
        .expect_err("missing zero-target inherit source errors");
    assert!(matches!(error.kind(), ScopeErrorKind::UndefinedSymbol(_)));

    let error = resolve(parse_str("let inherit (src); in 1").expect("source parses"))
        .expect_err("missing let zero-target inherit source errors");
    assert!(matches!(error.kind(), ScopeErrorKind::UndefinedSymbol(_)));

    resolved("let inherit (src); src = {}; in 1");
}

#[test]
fn rec_inherit_targets_are_self_visible_but_sources_are_outer() {
    let ast = resolved("let x = 1; in rec { inherit x; y = x; }");
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Children(bindings) = node(&ast, body).data else {
        panic!("rec attrset payload expected");
    };
    let inherit = child_ids(&ast, bindings)[0];
    let resolution = inherit_resolution(&ast, inherit);
    let source = resolution.sources[0].source;
    assert_eq!(node(&ast, source).kind, NodeKind::UpvalVar);
    assert_eq!(upval(&ast, source), (1, 0));

    let y_value = binding_value(&ast, child_ids(&ast, bindings)[1]);
    assert_eq!(node(&ast, y_value).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, y_value), 0);
}

#[test]
fn rejects_computed_let_binding_names() {
    let error = resolve(parse_str("let ${name} = 1; in 1").expect("source parses"))
        .expect_err("computed let target errors");
    assert_eq!(error.kind(), &ScopeErrorKind::DynamicLetBinding);

    let error = resolve(parse_str(r#"let ${"x" + "y"} = 1; in 1"#).expect("source parses"))
        .expect_err("computed let target errors");
    assert_eq!(error.kind(), &ScopeErrorKind::DynamicLetBinding);

    let error = resolve(parse_str(r#"let ${"a${"b"}"} = 1; in 1"#).expect("source parses"))
        .expect_err("computed let target errors");
    assert_eq!(error.kind(), &ScopeErrorKind::DynamicLetBinding);
}

#[test]
fn literal_interpolated_let_binding_names_are_static() {
    let ast = resolved(r#"let ${"x"} = 1; in x"#);
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    assert_eq!(node(&ast, body).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, body), 0);

    let ast = resolved(r#"let ${"a"}.b = 1; in a.b"#);
    let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let NodeData::Select { receiver, .. } = node(&ast, body).data else {
        panic!("select payload expected");
    };
    assert_eq!(node(&ast, receiver).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, receiver), 0);
}

#[test]
fn nested_dynamic_let_attr_names_resolve_after_static_prefix() {
    let ast = resolved("let name = \"b\"; a.${name} = 1; in a");
    let NodeData::LetIn { bindings, .. } = node(&ast, ast.root).data else {
        panic!("let-in payload expected");
    };
    let a_value = binding_value(&ast, child_ids(&ast, bindings)[1]);
    let NodeData::Children(nested_bindings) = node(&ast, a_value).data else {
        panic!("nested attrset payload expected");
    };
    let NodeData::Binding { path, .. } = node(&ast, child_ids(&ast, nested_bindings)[0]).data
    else {
        panic!("nested binding payload expected");
    };
    let dynamic_segment = child_ids(&ast, path)[0];
    let NodeData::Node(dynamic_name) = node(&ast, dynamic_segment).data else {
        panic!("dynamic attr segment expected");
    };
    assert_eq!(node(&ast, dynamic_name).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, dynamic_name), 0);
}

#[test]
fn backslash_escaped_indented_string_interpolation_does_not_resolve_a_symbol() {
    resolved(r"''''\${PORT}''");
}

#[test]
fn formal_defaults_and_aliases_use_lambda_slots() {
    let ast = resolved("{ a, b ? a, ... }@args: args");
    let frame = ast
        .scopes
        .frame_for_node(ast.root)
        .expect("lambda frame exists");
    assert_eq!(ast.scopes.frames()[frame.index()].slot_count, 3);

    let NodeData::Pair {
        first: pattern,
        second: body,
    } = node(&ast, ast.root).data
    else {
        panic!("lambda payload expected");
    };
    assert_eq!(node(&ast, body).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, body), 2);

    let NodeData::FormalSet { formals, .. } = node(&ast, pattern).data else {
        panic!("formal-set payload expected");
    };
    let b_formal = child_ids(&ast, formals)[1];
    let NodeData::Formal {
        default: Some(default),
        ..
    } = node(&ast, b_formal).data
    else {
        panic!("formal default expected");
    };
    assert_eq!(node(&ast, default).kind, NodeKind::LocalVar);
    assert_eq!(local_slot(&ast, default), 0);
}
