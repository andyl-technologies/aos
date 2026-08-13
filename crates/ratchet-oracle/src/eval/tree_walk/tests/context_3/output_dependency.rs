//! Output dependency context primop coverage.

use super::*;

#[test]
fn unsafe_discard_output_dependency_primop_downgrades_deep_contexts() {
    assert_eq!(
        eval_string_bytes("builtins.unsafeDiscardOutputDependency \"abc\""),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes("builtins.unsafeDiscardOutputDependency { outPath = \"abc\"; }"),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { unsafeDiscardOutputDependency = value: \"shadow\"; }; in builtins.unsafeDiscardOutputDependency \"abc\""
        ),
        b"shadow"
    );

    let ir = lower("builtins.unsafeDiscardOutputDependency \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("unsafeDiscardOutputDependency argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source_path = b"/nix/store/source";
    let deep_path = b"/nix/store/deep.drv";
    let output_path = b"/nix/store/output.drv";
    let context = StringContext::new(vec![
        ContextElement::deep_derivation(deep_path.to_vec()).expect("deep context is valid"),
        ContextElement::opaque_path(deep_path.to_vec()).expect("opaque context is valid"),
        ContextElement::opaque_path(source_path.to_vec()).expect("source context is valid"),
        ContextElement::single_output(output_path.to_vec(), b"out".to_vec())
            .expect("output context is valid"),
    ]);
    let value = evaluator
        .heap
        .alloc_string(NixString::new(b"x".to_vec(), context))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_unsafe_discard_output_dependency_primop(
            ir.root,
            root.span,
            argument,
            argument_span,
            value,
        )
        .expect("unsafeDiscardOutputDependency evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result string exists");

    assert_eq!(string.bytes(), b"x");
    assert_eq!(string.context().len(), 3);
    assert!(string.context().contains(
        &ContextElement::opaque_path(source_path.to_vec()).expect("source context builds")
    ));
    assert!(string.context().contains(
        &ContextElement::opaque_path(deep_path.to_vec()).expect("deep path context builds")
    ));
    assert!(
        string.context().contains(
            &ContextElement::single_output(output_path.to_vec(), b"out".to_vec())
                .expect("output context builds")
        )
    );
    assert!(!string.context().contains(
        &ContextElement::deep_derivation(deep_path.to_vec()).expect("deep context builds")
    ));
}

#[test]
fn unsafe_discard_output_dependency_primop_coerces_argument() {
    let ir = lower("builtins.unsafeDiscardOutputDependency 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("integer coercion is rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);
}
