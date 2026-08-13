//! Tests for core expression lowering, thunking, shapes, and caches.

use super::super::*;
use super::*;
use crate::resolve;
use crate::syntax::parse_str;

#[test]
fn lowers_let_lambda_application_to_resolved_ir() {
    let ir = lowered("let x = 1; f = y: x + y; in f 41");
    let root = node(&ir, ir.root);
    assert_eq!(root.kind, IrKind::Let);
    let IrData::Let { bindings, body, .. } = root.data else {
        panic!("let payload expected");
    };
    assert_eq!(bindings.len(), 2);
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, second } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::LocalVar);
    assert_eq!(node(&ir, second).kind, IrKind::Int);
}

#[test]
fn invalid_lambda_pattern_shapes_are_rejected_before_ir() {
    let pattern = NodeId::new(0);
    let body = NodeId::new(1);
    let root = NodeId::new(2);
    let pattern_span = Span::new(0, 1);
    let error = lower(manual_resolved_ast(
        root,
        vec![
            Node::new(NodeKind::Int, pattern_span, NodeData::Int(1)),
            Node::new(NodeKind::Int, Span::new(4, 5), NodeData::Int(2)),
            Node::new(
                NodeKind::Lambda,
                Span::new(0, 5),
                NodeData::Pair {
                    first: pattern,
                    second: body,
                },
            ),
        ],
    ))
    .expect_err("non-pattern lambda heads are malformed AST");

    assert_eq!(
        error.kind(),
        &IrErrorKind::InvalidNodeShape {
            kind: NodeKind::Int,
            expected: "lambda pattern",
        }
    );
    assert_eq!(error.span(), pattern_span);
}

#[test]
fn lowers_global_bool_and_null_literals_after_resolution() {
    let true_ir = lowered("true");
    assert_eq!(root_node(&true_ir).kind, IrKind::Bool);
    assert_eq!(root_node(&true_ir).data, IrData::Bool(true));

    let false_ir = lowered("false");
    assert_eq!(root_node(&false_ir).kind, IrKind::Bool);
    assert_eq!(root_node(&false_ir).data, IrData::Bool(false));

    let null_ir = lowered("null");
    assert_eq!(root_node(&null_ir).kind, IrKind::Null);
    assert_eq!(root_node(&null_ir).data, IrData::None);
}

#[test]
fn shadowed_bool_and_null_names_remain_lexical_variables() {
    let ir = lowered("let true = 1; null = 2; in [ true null ]");
    let root = root_node(&ir);
    let IrData::Let { body, .. } = root.data else {
        panic!("let payload expected");
    };
    let IrData::Children(elements) = node(&ir, body).data else {
        panic!("list payload expected");
    };
    let elements = ir.arena.child_slice(elements).expect("list slice exists");
    assert_eq!(
        node(&ir, thunk_inner(&ir, elements[0])).kind,
        IrKind::LocalVar
    );
    assert_eq!(
        node(&ir, thunk_inner(&ir, elements[1])).kind,
        IrKind::LocalVar
    );
}

#[test]
fn pipe_binary_operands_lower_piped_side_lazily() {
    let division_lhs = NodeId::new(0);
    let division_rhs = NodeId::new(1);
    let division = NodeId::new(2);
    let function_side = NodeId::new(3);
    let pipe = NodeId::new(4);
    let pipe_right = lower(manual_resolved_ast(
        pipe,
        vec![
            Node::new(NodeKind::Int, Span::new(0, 1), NodeData::Int(1)),
            Node::new(NodeKind::Int, Span::new(4, 5), NodeData::Int(0)),
            Node::new(
                NodeKind::BinOp,
                Span::new(0, 5),
                NodeData::Binary {
                    op: BinOpKind::Div,
                    lhs: division_lhs,
                    rhs: division_rhs,
                },
            ),
            Node::new(NodeKind::Int, Span::new(9, 10), NodeData::Int(7)),
            Node::new(
                NodeKind::BinOp,
                Span::new(0, 10),
                NodeData::Binary {
                    op: BinOpKind::PipeRight,
                    lhs: division,
                    rhs: function_side,
                },
            ),
        ],
    ))
    .expect("forward pipe IR lowers");
    let IrData::Binary { lhs, rhs, .. } = root_node(&pipe_right).data else {
        panic!("pipe payload expected");
    };
    assert_eq!(
        node(&pipe_right, thunk_inner(&pipe_right, lhs)).kind,
        IrKind::BinOp
    );
    assert_eq!(node(&pipe_right, rhs).kind, IrKind::Int);

    let function_side = NodeId::new(0);
    let division_lhs = NodeId::new(1);
    let division_rhs = NodeId::new(2);
    let division = NodeId::new(3);
    let pipe = NodeId::new(4);
    let pipe_left = lower(manual_resolved_ast(
        pipe,
        vec![
            Node::new(NodeKind::Int, Span::new(0, 1), NodeData::Int(7)),
            Node::new(NodeKind::Int, Span::new(5, 6), NodeData::Int(1)),
            Node::new(NodeKind::Int, Span::new(9, 10), NodeData::Int(0)),
            Node::new(
                NodeKind::BinOp,
                Span::new(5, 10),
                NodeData::Binary {
                    op: BinOpKind::Div,
                    lhs: division_lhs,
                    rhs: division_rhs,
                },
            ),
            Node::new(
                NodeKind::BinOp,
                Span::new(0, 10),
                NodeData::Binary {
                    op: BinOpKind::PipeLeft,
                    lhs: function_side,
                    rhs: division,
                },
            ),
        ],
    ))
    .expect("reverse pipe IR lowers");
    let IrData::Binary { lhs, rhs, .. } = root_node(&pipe_left).data else {
        panic!("pipe payload expected");
    };
    assert_eq!(node(&pipe_left, lhs).kind, IrKind::Int);
    assert_eq!(
        node(&pipe_left, thunk_inner(&pipe_left, rhs)).kind,
        IrKind::BinOp
    );
}

#[test]
fn with_shadowed_bool_name_remains_global() {
    let ir = lowered("with { true = 1; }; true");
    let IrData::Pair { second, .. } = root_node(&ir).data else {
        panic!("with payload expected");
    };
    assert_eq!(node(&ir, second).kind, IrKind::Bool);
}

#[test]
fn default_core_lowering_rejects_dynamic_scope_variables() {
    let resolved =
        resolve(parse_str("with {}; missing").expect("source parses")).expect("source resolves");
    let error = lower(resolved).expect_err("plain core lowering has no dynamic-scope op");

    assert_eq!(
        error.kind(),
        &IrErrorKind::UnsupportedDialectOp {
            operation: "dynamic scope variable",
        }
    );
}

#[test]
fn default_core_lowering_specializes_with_builtins_scope_variables() {
    let ir = lowered("with builtins; trace");
    let IrData::Pair { second, .. } = root_node(&ir).data else {
        panic!("with payload expected");
    };
    let node = node(&ir, second);
    assert_eq!(node.kind, IrKind::BuiltinAttr);
    let IrData::Symbol(symbol) = node.data else {
        panic!("builtin attr payload expected");
    };
    assert_eq!(ir.symbols.resolve(symbol), Some(b"trace".as_slice()));

    let resolved = resolve(parse_str("with { trace = 1; }; trace").expect("source parses"))
        .expect("source resolves");
    assert!(matches!(
        lower(resolved).map(|_| ()),
        Err(error)
            if error.kind()
                == &IrErrorKind::UnsupportedDialectOp {
                    operation: "dynamic scope variable"
                }
    ));

    let resolved =
        resolve(parse_str("with builtins; with { trace = 1; }; trace").expect("source parses"))
            .expect("source resolves");
    assert!(matches!(
        lower(resolved).map(|_| ()),
        Err(error)
            if error.kind()
                == &IrErrorKind::UnsupportedDialectOp {
                    operation: "dynamic scope variable"
                }
    ));

    let resolved = resolve(parse_str("with builtins; trace").expect("source parses"))
        .expect("source resolves");
    assert!(matches!(
        lower_with_options(resolved, IrLowerOptions::with_dynamic_builtin_scope()).map(|_| ()),
        Err(error)
            if error.kind()
                == &IrErrorKind::UnsupportedDialectOp {
                    operation: "dynamic scope variable"
                }
    ));
}

#[test]
fn with_var_chains_point_to_lowered_scopes_inner_first() {
    let ir = lowered_nix("with { outer = 1; }; with { inner = 2; }; missing");
    let IrData::Pair {
        first: outer,
        second: inner_with,
    } = root_node(&ir).data
    else {
        panic!("outer with payload expected");
    };
    let IrData::Pair {
        first: inner,
        second: body,
    } = node(&ir, inner_with).data
    else {
        panic!("inner with payload expected");
    };
    let IrData::DialectScopeVar { chain, site, .. } = node(&ir, body).data else {
        panic!("with-var payload expected");
    };

    let chain = &ir.with_chains[chain as usize];
    assert_eq!(chain.scopes.as_ref(), &[inner, outer]);
    assert_eq!(site.as_u32(), 0);
}

#[test]
fn with_scrutinees_are_explicit_lazy_scope_nodes() {
    let ir = lowered_nix("with { a = 1; }; a");
    let IrData::Pair {
        first: scope,
        second: body,
    } = root_node(&ir).data
    else {
        panic!("with payload expected");
    };
    assert_eq!(node(&ir, scope).kind, IrKind::ThunkAlloc);
    assert_eq!(node(&ir, thunk_inner(&ir, scope)).kind, IrKind::AttrSet);

    let IrData::DialectScopeVar { chain, site, .. } = node(&ir, body).data else {
        panic!("with-var payload expected");
    };
    assert_eq!(ir.with_chains[chain as usize].scopes.as_ref(), &[scope]);
    assert_eq!(site.as_u32(), 0);
}

#[test]
fn with_var_select_and_has_attr_sites_share_one_monotonic_namespace() {
    let ir = lowered_nix("with { a = 1; }; if ({ b = 2; } ? b) then a + ({ c = 3; }).c else 0");
    let IrData::Pair { second: body, .. } = root_node(&ir).data else {
        panic!("with payload expected");
    };
    let IrData::Triple {
        first: condition,
        second: then_branch,
        ..
    } = node(&ir, body).data
    else {
        panic!("if payload expected");
    };
    let IrData::Binary { lhs, rhs, .. } = node(&ir, then_branch).data else {
        panic!("then branch is addition");
    };

    assert_eq!(lookup_site(&ir, condition).as_u32(), 0);
    assert_eq!(lookup_site(&ir, lhs).as_u32(), 1);
    assert_eq!(lookup_site(&ir, rhs).as_u32(), 2);
}

#[test]
fn global_var_select_and_has_attr_sites_share_one_monotonic_namespace() {
    let ir = lowered("if __nixPath then ({ a = 1; } ? a) else ({ b = 2; }).b");
    let IrData::Triple {
        first: condition,
        second: then_branch,
        third: else_branch,
    } = root_node(&ir).data
    else {
        panic!("if payload expected");
    };

    assert_eq!(node(&ir, condition).kind, IrKind::GlobalVar);
    assert_eq!(lookup_site(&ir, condition).as_u32(), 0);
    assert_eq!(lookup_site(&ir, then_branch).as_u32(), 1);
    assert_eq!(lookup_site(&ir, else_branch).as_u32(), 2);
}

#[test]
fn bool_and_null_literals_are_not_thunked_in_lists() {
    let ir = lowered("[ true null false ]");
    let IrData::Children(elements) = root_node(&ir).data else {
        panic!("list payload expected");
    };
    let elements = ir.arena.child_slice(elements).expect("list slice exists");
    assert_eq!(node(&ir, elements[0]).kind, IrKind::Bool);
    assert_eq!(node(&ir, elements[1]).kind, IrKind::Null);
    assert_eq!(node(&ir, elements[2]).kind, IrKind::Bool);
}

#[test]
fn lowers_direct_derivation_strict_to_effectful_boundary() {
    for source in [
        "derivationStrict { name = \"x\"; }",
        "builtins.derivationStrict { name = \"x\"; }",
    ] {
        let ir = lowered_nix(source);
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::PrimOp);
        assert_eq!(root.effect, TEST_NIX_EFFECTFUL);
        let IrData::DialectNode {
            op: TEST_DERIVATION_STRICT_OP,
            argument,
        } = root.data
        else {
            panic!("derivationStrict payload expected");
        };
        assert_eq!(node(&ir, argument).kind, IrKind::AttrSet);
    }
}

#[test]
fn shadowed_derivation_strict_stays_an_application() {
    let ir = lowered("let derivationStrict = x: x; in derivationStrict 1");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::Apply);
    let IrData::Pair { first, .. } = node(&ir, body).data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::LocalVar);
}

#[test]
fn shadowed_builtins_derivation_strict_stays_a_select_application() {
    let ir = lowered("let builtins = { derivationStrict = x: x; }; in builtins.derivationStrict 1");
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
fn with_shadowed_derivation_strict_lowers_to_effectful_boundary() {
    let ir = lowered_nix("with { derivationStrict = x: x; }; derivationStrict 1");
    let IrData::Pair { second: body, .. } = root_node(&ir).data else {
        panic!("with payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::PrimOp);
    assert_eq!(node(&ir, body).effect, TEST_NIX_EFFECTFUL);
    let IrData::DialectNode {
        op: TEST_DERIVATION_STRICT_OP,
        argument,
    } = node(&ir, body).data
    else {
        panic!("derivationStrict payload expected");
    };
    assert_eq!(node(&ir, argument).kind, IrKind::Int);
}

#[test]
fn select_default_derivation_strict_stays_a_select_application() {
    let ir = lowered("(builtins.derivationStrict or (x: x)) { name = \"x\"; }");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::Apply);
    let IrData::Pair { first, .. } = root.data else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, first).kind, IrKind::Select);
}

#[test]
fn static_builtin_selects_lower_to_builtin_attr_nodes() {
    let ir = lowered("builtins.length");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::BuiltinAttr);
    assert_eq!(root.effect, EffectClass::pure());
    let IrData::Symbol(symbol) = root.data else {
        panic!("builtin attr payload expected");
    };
    assert_eq!(symbol_text(&ir, symbol), b"length");

    let ir = lowered("builtins.currentSystem");
    let root = root_node(&ir);
    assert_eq!(root.kind, IrKind::BuiltinAttr);
    let IrData::Symbol(symbol) = root.data else {
        panic!("builtin attr payload expected");
    };
    assert_eq!(symbol_text(&ir, symbol), b"currentSystem");
}

#[test]
fn non_static_builtin_selects_remain_select_nodes() {
    for source in [
        "builtins.length or 42",
        "builtins.__missing",
        "builtins.length.foo",
        "let builtins = { length = x: 42; }; in builtins.length",
    ] {
        let ir = lowered(source);
        let root = root_node(&ir);
        match root.data {
            IrData::Let { body, .. } => assert_eq!(node(&ir, body).kind, IrKind::Select),
            _ => assert_eq!(root.kind, IrKind::Select),
        }
    }
}

#[test]
fn dynamic_builtin_scope_keeps_static_builtin_selects_dynamic() {
    let resolved =
        resolve(parse_str("builtins.length").expect("source parses")).expect("source resolves");
    let ir = lower_with_options(resolved, IrLowerOptions::with_dynamic_builtin_scope())
        .expect("IR lowers");

    assert_eq!(root_node(&ir).kind, IrKind::Select);
}
#[test]
fn materializes_thunks_at_lazy_binding_and_list_positions() {
    let ir = lowered("let x = y: y; in [ x 1 \"s\" ]");
    let root = node(&ir, ir.root);
    let IrData::Let { bindings, body, .. } = root.data else {
        panic!("let payload expected");
    };
    let binding = ir.bindings[bindings.start as usize];
    assert_eq!(node(&ir, binding.value).kind, IrKind::ThunkAlloc);
    let list = node(&ir, body);
    let IrData::Children(elements) = list.data else {
        panic!("list elements expected");
    };
    let elements = ir.arena.child_slice(elements).expect("list slice exists");
    assert_eq!(node(&ir, elements[0]).kind, IrKind::ThunkAlloc);
    assert_eq!(node(&ir, elements[1]).kind, IrKind::Int);
    assert_eq!(node(&ir, elements[2]).kind, IrKind::Str);
}

#[test]
fn literal_interpolated_let_binding_names_lower_as_static_keys() {
    let ir = lowered(r#"let ${"x"} = 1; in x"#);
    let root = root_node(&ir);
    let IrData::Let { bindings, body, .. } = root.data else {
        panic!("let payload expected");
    };
    let binding = ir.bindings[bindings.start as usize];
    let IrAttrPathSegment::Static(symbol) = binding.key else {
        panic!("literal interpolated let key should be static");
    };
    assert_eq!(symbol_text(&ir, symbol), b"x");
    assert_eq!(node(&ir, body).kind, IrKind::LocalVar);
}

#[test]
fn unsupported_literal_values_stay_lazy() {
    let ir = lowered("let p = ./foo; s = <nixpkgs>; in 1");
    let root = node(&ir, ir.root);
    let IrData::Let { bindings, .. } = root.data else {
        panic!("let payload expected");
    };
    let start = bindings.start as usize;
    let end = start + bindings.len();
    let bindings = ir.bindings[start..end]
        .iter()
        .map(|binding| binding.value)
        .collect::<Vec<_>>();

    assert_eq!(node(&ir, bindings[0]).kind, IrKind::ThunkAlloc);
    assert_eq!(node(&ir, thunk_inner(&ir, bindings[0])).kind, IrKind::Path);
    assert_eq!(node(&ir, bindings[1]).kind, IrKind::ThunkAlloc);
    assert_eq!(
        node(&ir, thunk_inner(&ir, bindings[1])).kind,
        IrKind::SearchPath
    );
}

#[test]
fn search_path_literals_capture_lexical_nix_path() {
    let ir = lowered("let __nixPath = []; in <a.nix>");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    let body = node(&ir, body);
    let IrData::SearchPath {
        literal,
        search_path: Some(search_path),
    } = body.data
    else {
        panic!("search-path payload with lexical list expected");
    };

    assert_eq!(symbol_text(&ir, literal), b"<a.nix>");
    assert_eq!(node(&ir, search_path).kind, IrKind::LocalVar);
}

#[test]
fn search_path_literals_ignore_with_bound_nix_path() {
    let ir = lowered("with { __nixPath = []; }; <a.nix>");
    let IrData::Pair { second, .. } = root_node(&ir).data else {
        panic!("with payload expected");
    };
    let body = node(&ir, second);
    let IrData::SearchPath {
        literal,
        search_path: None,
    } = body.data
    else {
        panic!("ambient search-path payload expected");
    };

    assert_eq!(symbol_text(&ir, literal), b"<a.nix>");
}

#[test]
fn bare_nix_path_is_a_magic_global_but_lexical_bindings_win() {
    let ir = lowered("__nixPath");
    assert_eq!(root_node(&ir).kind, IrKind::GlobalVar);

    let ir = lowered("let __nixPath = []; in __nixPath");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    assert_eq!(node(&ir, body).kind, IrKind::LocalVar);

    let ir = lowered("with { __nixPath = []; }; __nixPath");
    let IrData::Pair { second, .. } = root_node(&ir).data else {
        panic!("with payload expected");
    };
    assert_eq!(node(&ir, second).kind, IrKind::GlobalVar);
}

#[test]
fn uri_literals_are_trivial_values() {
    let ir = lowered("let u = http://example.test; in [ u ]");
    let root = node(&ir, ir.root);
    let IrData::Let { bindings, body, .. } = root.data else {
        panic!("let payload expected");
    };
    let binding = ir.bindings[bindings.start as usize];
    assert_eq!(node(&ir, binding.value).kind, IrKind::Uri);

    let list = node(&ir, body);
    let IrData::Children(elements) = list.data else {
        panic!("list elements expected");
    };
    let elements = ir.arena.child_slice(elements).expect("list slice exists");
    assert_eq!(node(&ir, elements[0]).kind, IrKind::ThunkAlloc);
}

#[test]
fn lowers_dynamic_attr_paths_to_side_table_segments() {
    let ir = lowered("let name = \"x\"; in { ${name} = 1; }.${name}");
    let root = node(&ir, ir.root);
    let IrData::Let { body, .. } = root.data else {
        panic!("let payload expected");
    };
    let select = node(&ir, body);
    let IrData::Select { path, .. } = select.data else {
        panic!("select payload expected");
    };
    assert!(matches!(
        ir.attr_paths[path.index()].as_ref(),
        [IrAttrPathSegment::Dynamic(_)]
    ));

    let ir = lowered(r#"{ ${"x" + ""} = 1; }"#);
    let root = root_node(&ir);
    let IrData::AttrSet { has_dynamic, .. } = root.data else {
        panic!("attrset payload expected");
    };
    assert!(has_dynamic);
}

#[test]
fn attrsets_reference_static_shapes_in_source_order() {
    let ir = lowered("{ a = 1; b = 2; c.d = 3; }");
    let root = root_node(&ir);
    let IrData::AttrSet {
        shape, has_dynamic, ..
    } = root.data
    else {
        panic!("attrset payload expected");
    };
    assert!(!has_dynamic);
    let keys = ir.shapes[shape.index()]
        .keys
        .iter()
        .map(|symbol| symbol_text(&ir, *symbol))
        .collect::<Vec<_>>();
    assert_eq!(keys, [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]);
}

#[test]
fn dynamic_attrset_shapes_keep_static_keys_and_dynamic_flag() {
    let ir = lowered("let name = \"x\"; in { ${name} = 1; a = 2; }");
    let IrData::Let { body, .. } = root_node(&ir).data else {
        panic!("let payload expected");
    };
    let IrData::AttrSet {
        shape, has_dynamic, ..
    } = node(&ir, body).data
    else {
        panic!("attrset payload expected");
    };
    assert!(has_dynamic);
    let keys = ir.shapes[shape.index()]
        .keys
        .iter()
        .map(|symbol| symbol_text(&ir, *symbol))
        .collect::<Vec<_>>();
    assert_eq!(keys, [b"a".as_slice()]);
}

#[test]
fn empty_attrsets_have_empty_shapes() {
    let ir = lowered("{}");
    let IrData::AttrSet {
        shape,
        has_dynamic,
        bindings,
        ..
    } = root_node(&ir).data
    else {
        panic!("attrset payload expected");
    };
    assert!(!has_dynamic);
    assert_eq!(bindings.len(), 0);
    assert!(ir.shapes[shape.index()].keys.is_empty());
}

#[test]
fn recursive_attrsets_keep_shape_and_frame() {
    let ir = lowered("rec { a = 1; }");
    let IrData::AttrSet {
        shape,
        recursive,
        frame,
        ..
    } = root_node(&ir).data
    else {
        panic!("attrset payload expected");
    };
    assert!(recursive);
    assert!(frame.is_some());
    let keys = ir.shapes[shape.index()]
        .keys
        .iter()
        .map(|symbol| symbol_text(&ir, *symbol))
        .collect::<Vec<_>>();
    assert_eq!(keys, [b"a".as_slice()]);
}

#[test]
fn assigns_stable_inline_cache_sites_to_lookups() {
    let ir = lowered("let x = { a = 1; b = 2; }; in [ x.a (x ? b) x.b ]");
    let root = node(&ir, ir.root);
    let IrData::Let { body, .. } = root.data else {
        panic!("let payload expected");
    };
    let IrData::Children(elements) = node(&ir, body).data else {
        panic!("list payload expected");
    };
    let elements = ir.arena.child_slice(elements).expect("list slice exists");
    let first = thunk_inner(&ir, elements[0]);
    let second = thunk_inner(&ir, elements[1]);
    let third = thunk_inner(&ir, elements[2]);

    assert_eq!(lookup_site(&ir, first).as_u32(), 0);
    assert_eq!(lookup_site(&ir, second).as_u32(), 1);
    assert_eq!(lookup_site(&ir, third).as_u32(), 2);
}

#[test]
fn inherit_from_targets_share_one_source_thunk() {
    let ir = lowered("let src = { name = 1; version = 2; }; in { inherit (src) name version; }");
    let root = node(&ir, ir.root);
    let IrData::Let { body, .. } = root.data else {
        panic!("let payload expected");
    };
    let IrData::AttrSet { bindings, .. } = node(&ir, body).data else {
        panic!("attrset payload expected");
    };
    assert_eq!(bindings.len(), 2);

    let first = ir.bindings[bindings.start as usize];
    let second = ir.bindings[bindings.start as usize + 1];
    let first_select = thunk_inner(&ir, first.value);
    let second_select = thunk_inner(&ir, second.value);
    assert_eq!(lookup_site(&ir, first_select).as_u32(), 0);
    assert_eq!(lookup_site(&ir, second_select).as_u32(), 1);
    let IrData::Select {
        receiver: first_receiver,
        ..
    } = node(&ir, first_select).data
    else {
        panic!("select payload expected");
    };
    let IrData::Select {
        receiver: second_receiver,
        ..
    } = node(&ir, second_select).data
    else {
        panic!("select payload expected");
    };
    assert_eq!(first_receiver, second_receiver);
    assert_eq!(
        node(&ir, thunk_inner(&ir, first_receiver)).kind,
        IrKind::LocalVar
    );
}
