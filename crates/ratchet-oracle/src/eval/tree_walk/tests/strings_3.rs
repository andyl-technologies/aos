//! Tree-walk evaluator tests: strings 3.

use super::*;

#[test]
fn string_add_rejects_non_string_rhs() {
    let ir = lower("\"a\" + 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("addition root has binary payload");
    };
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&ir).expect_err("integer rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn string_add_evaluates_rhs_before_type_checking_it() {
    let ir = lower("\"a\" + (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("addition root has binary payload");
    };
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&ir).expect_err("rhs evaluation error wins");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn numeric_add_rejects_string_rhs_as_non_numeric() {
    let ir = lower("1 + \"a\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("addition root has binary payload");
    };
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&ir).expect_err("string rhs is invalid for numeric add");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "number",
            actual: ValueTag::String,
        }
    );
    assert_eq!(error.span(), rhs_span);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn integer_literals_cover_i64_boundaries() {
    assert_eq!(eval("9223372036854775807").as_int(), Ok(i64::MAX));
    assert_eq!(
        eval("0 + (-9223372036854775807 - 1)").as_int(),
        Ok(i64::MIN)
    );
}

#[test]
fn addition_rejects_mismatched_operand_kinds() {
    for source in [
        "true + false",
        "null + null",
        "[ 1 ] + [ 2 ]",
        "{ a = 1; } + { b = 2; }",
        "(x: x) + (x: x)",
    ] {
        eval_whnf_owned(&lower(source)).expect_err("mismatched addition operands are invalid");
    }
}

#[test]
fn addition_coerces_left_attrsets_with_raw_string_rules() {
    let (dir, path) = temp_file_with_bytes("attrs-add-path", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_string_bytes(r#"{ __toString = self: "left"; } + "right""#),
        b"leftright"
    );
    assert_eq!(
        eval_string_bytes(r#"{ outPath = "left"; } + { outPath = "right"; }"#),
        b"leftright"
    );
    assert_eq!(
        eval_string_bytes(&format!("{{ __toString = self: {path}; }} + {path}")),
        format!("{path}{path}").as_bytes()
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "builtins.getContext ({{ __toString = self: {path}; }} + {path})"
        )),
        b"{}"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn addition_type_matrix_accepts_only_nix_legal_operand_pairs() {
    let (dir, operands) = add_operator_matrix_operands("add-matrix");

    for left in &operands {
        for right in &operands {
            let source = add_operator_matrix_source(left, right);
            if add_operator_matrix_cell_is_legal(left.kind, right.kind) {
                assert_eq!(
                    eval(&source).as_bool(),
                    Ok(true),
                    "{:?} + {:?} should be legal",
                    left.kind,
                    right.kind
                );
            } else {
                assert!(
                    eval_whnf_owned(&lower(&source)).is_err(),
                    "{:?} + {:?} should be illegal",
                    left.kind,
                    right.kind
                );
            }
        }
    }

    fs::remove_dir_all(dir).expect("matrix temp directory removes");
}

#[test]
fn non_owning_eval_rejects_string_add_heap_values() {
    let ir = lower("\"a\" + \"b\"");
    let error = eval_whnf(&ir).expect_err("string add value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::String,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );
}

#[test]
fn non_owning_eval_rejects_heap_values() {
    let ir = lower("\"hello\"");
    let error = eval_whnf(&ir).expect_err("string value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::String,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );

    let list_ir = lower("[]");
    let error = eval_whnf(&list_ir).expect_err("list value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: list_ir.root,
            tag: ValueTag::List,
        }
    );
    assert_eq!(
        error.span(),
        list_ir.arena.node(list_ir.root).expect("root exists").span
    );

    let non_empty_list_ir = lower("[ 1 ]");
    let error = eval_whnf(&non_empty_list_ir).expect_err("non-empty list needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: non_empty_list_ir.root,
            tag: ValueTag::List,
        }
    );
    assert_eq!(
        error.span(),
        non_empty_list_ir
            .arena
            .node(non_empty_list_ir.root)
            .expect("root exists")
            .span
    );

    let attrs_ir = lower("{}");
    let error = eval_whnf(&attrs_ir).expect_err("attrset value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: attrs_ir.root,
            tag: ValueTag::Attrs,
        }
    );
    assert_eq!(
        error.span(),
        attrs_ir
            .arena
            .node(attrs_ir.root)
            .expect("root exists")
            .span
    );

    let lambda_ir = lower("x: x");
    let error = eval_whnf(&lambda_ir).expect_err("lambda value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: lambda_ir.root,
            tag: ValueTag::Lambda,
        }
    );
    assert_eq!(
        error.span(),
        lambda_ir
            .arena
            .node(lambda_ir.root)
            .expect("root exists")
            .span
    );
}

#[test]
fn invalid_expression_nodes_report_kind_and_span() {
    for (kind, data) in [
        (
            IrKind::FormalSet,
            IrData::FormalSet {
                formals: IrChildSlice::new(0, 0),
                ellipsis: false,
                alias: None,
            },
        ),
        (
            IrKind::Formal,
            IrData::Formal {
                name: Symbol::new(0),
                default: None,
            },
        ),
    ] {
        let root = IrId::new(0);
        let span = Span::new(0, 1);
        let ir = manual_ir(root, vec![pure_node(kind, span, data)]);
        let error = eval_whnf(&ir).expect_err("helper nodes are not directly evaluable");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidNodeKind { id: root, kind }
        );
        assert_eq!(error.span(), span);
    }
}

#[test]
fn pipe_operators_apply_functions() {
    let mut symbols = SymbolTable::new();
    let to_string = symbols.intern(b"toString").expect("symbol interns");
    let site = IrInlineCacheSiteId::new(0);

    let forward = manual_ir_with_symbols(
        IrId::new(2),
        vec![
            pure_node(IrKind::Int, Span::new(0, 2), IrData::Int(42)),
            pure_node(
                IrKind::GlobalVar,
                Span::new(6, 14),
                IrData::GlobalVar {
                    site,
                    symbol: to_string,
                },
            ),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 14),
                IrData::Binary {
                    op: BinOpKind::PipeRight,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        symbols.clone(),
    );
    let forward = eval_whnf_owned(&forward).expect("forward pipe evaluates");
    assert_eq!(
        forward
            .heap()
            .get_string(forward.value())
            .expect("forward pipe returns a string")
            .bytes(),
        b"42",
    );

    let reverse = manual_ir_with_symbols(
        IrId::new(2),
        vec![
            pure_node(
                IrKind::GlobalVar,
                Span::new(0, 8),
                IrData::GlobalVar {
                    site,
                    symbol: to_string,
                },
            ),
            pure_node(IrKind::Int, Span::new(12, 13), IrData::Int(7)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 13),
                IrData::Binary {
                    op: BinOpKind::PipeLeft,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        symbols,
    );
    let reverse = eval_whnf_owned(&reverse).expect("reverse pipe evaluates");
    assert_eq!(
        reverse
            .heap()
            .get_string(reverse.value())
            .expect("reverse pipe returns a string")
            .bytes(),
        b"7",
    );
}

#[test]
fn pipe_operators_pass_piped_operand_lazily() {
    let mut symbols = SymbolTable::new();
    let x = symbols.intern(b"x").expect("symbol interns");
    let frames = vec![FrameInfo {
        slot_count: 1,
        captures: Vec::new().into_boxed_slice(),
        rec: false,
        has_with: false,
    }];

    fn ignored_division_pipe(
        op: BinOpKind,
        x: Symbol,
        symbols: SymbolTable,
        frames: Vec<FrameInfo>,
    ) -> Ir {
        let (lhs, rhs) = match op {
            BinOpKind::PipeRight => (IrId::new(6), IrId::new(2)),
            BinOpKind::PipeLeft => (IrId::new(2), IrId::new(6)),
            _ => unreachable!("test helper only builds pipe operators"),
        };
        manual_ir_with_symbols_and_frames(
            IrId::new(7),
            vec![
                pure_node(
                    IrKind::Formal,
                    Span::new(0, 1),
                    IrData::Formal {
                        name: x,
                        default: None,
                    },
                ),
                pure_node(IrKind::Int, Span::new(3, 4), IrData::Int(5)),
                pure_node(
                    IrKind::Lambda,
                    Span::new(0, 4),
                    IrData::Lambda {
                        pattern: IrId::new(0),
                        body: IrId::new(1),
                        frame: Some(FrameId::new(0)),
                    },
                ),
                pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(1)),
                pure_node(IrKind::Int, Span::new(12, 13), IrData::Int(0)),
                pure_node(
                    IrKind::BinOp,
                    Span::new(8, 13),
                    IrData::Binary {
                        op: BinOpKind::Div,
                        lhs: IrId::new(3),
                        rhs: IrId::new(4),
                    },
                ),
                pure_node(
                    IrKind::ThunkAlloc,
                    Span::new(8, 13),
                    IrData::Node(IrId::new(5)),
                ),
                pure_node(
                    IrKind::BinOp,
                    Span::new(0, 18),
                    IrData::Binary { op, lhs, rhs },
                ),
            ],
            symbols,
            frames,
        )
    }

    for (op, label) in [
        (BinOpKind::PipeRight, "forward pipe"),
        (BinOpKind::PipeLeft, "reverse pipe"),
    ] {
        let ir = ignored_division_pipe(op, x, symbols.clone(), frames.clone());
        assert_eq!(
            eval_whnf(&ir)
                .unwrap_or_else(|_| panic!("{label} does not force ignored argument"))
                .as_int(),
            Ok(5),
            "{label}",
        );
    }
}

#[test]
fn pipe_operators_report_non_callable_function_side() {
    let function = IrId::new(0);
    let root = IrId::new(1);
    let function_span = Span::new(5, 6);
    let forward = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, function_span, IrData::Int(1)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 6),
                IrData::Binary {
                    op: BinOpKind::PipeRight,
                    lhs: IrId::new(99),
                    rhs: function,
                },
            ),
        ],
    );
    let error = eval_whnf(&forward).expect_err("forward pipe function must be callable");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "lambda",
            actual: ValueTag::Int,
        },
    );
    assert_eq!(error.span(), function_span);

    let function_span = Span::new(0, 1);
    let reverse = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, function_span, IrData::Int(1)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 6),
                IrData::Binary {
                    op: BinOpKind::PipeLeft,
                    lhs: function,
                    rhs: IrId::new(99),
                },
            ),
        ],
    );
    let error = eval_whnf(&reverse).expect_err("reverse pipe function must be callable");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "lambda",
            actual: ValueTag::Int,
        },
    );
    assert_eq!(error.span(), function_span);
}

#[test]
fn invalid_node_ids_are_reported() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::new(&ir);
    let missing = IrId::new(99);
    let error = evaluator
        .eval_node(missing)
        .expect_err("missing node is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidNodeId { id: missing }
    );
    assert_eq!(error.span(), Span::default());
}

#[test]
fn malformed_literal_payloads_are_reported() {
    let cases = [
        (IrKind::Int, IrData::None, "integer payload"),
        (IrKind::Float, IrData::None, "float payload"),
        (IrKind::Bool, IrData::None, "boolean payload"),
        (IrKind::Null, IrData::Bool(false), "empty payload"),
        (IrKind::Str, IrData::None, "string symbol payload"),
        (IrKind::List, IrData::None, "list children"),
        (IrKind::AttrSet, IrData::None, "attrset payload"),
    ];

    for (index, (kind, data, expected)) in cases.into_iter().enumerate() {
        let root = IrId::new(0);
        let span = Span::new(index as u32, index as u32 + 1);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(kind, span, EffectClass::pure(), data)],
            Vec::new(),
        );
        let ir = empty_ir(root, arena);
        let error = eval_whnf(&ir).expect_err("malformed literal is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: root,
                kind,
                expected,
            }
        );
        assert_eq!(error.span(), span);
    }
}

#[test]
fn malformed_variable_and_let_payloads_are_reported() {
    let cases = [
        (IrKind::LocalVar, "local payload"),
        (IrKind::UpvalVar, "upvalue payload"),
        (IrKind::Let, "let payload"),
        (IrKind::With, "with pair"),
    ];

    for (index, (kind, expected)) in cases.into_iter().enumerate() {
        let root = IrId::new(0);
        let span = Span::new(10 + index as u32, 11 + index as u32);
        let ir = manual_ir(root, vec![pure_node(kind, span, IrData::None)]);
        let error = eval_whnf(&ir).expect_err("malformed variable or let is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: root,
                kind,
                expected,
            }
        );
        assert_eq!(error.span(), span);
    }
}

#[test]
fn malformed_function_payloads_are_reported() {
    let cases = [
        (IrKind::Lambda, "lambda payload"),
        (IrKind::Apply, "application pair"),
    ];

    for (index, (kind, expected)) in cases.into_iter().enumerate() {
        let root = IrId::new(0);
        let span = Span::new(20 + index as u32, 21 + index as u32);
        let ir = manual_ir(root, vec![pure_node(kind, span, IrData::None)]);
        let error = eval_whnf(&ir).expect_err("malformed function node is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: root,
                kind,
                expected,
            }
        );
        assert_eq!(error.span(), span);
    }
}
