//! Tree-walk evaluator tests: strings 2.

use super::*;

/// Chunk-F corpus regression (`lib/hardening.nix:116` via `pkgs.gnu-efi`):
/// both arguments must be forced to WHNF before type-checking, exactly as
/// C++ Nix's `forceString` / `forceList` — a thunked list (for example a
/// function-call result) is not a type error.
#[test]
fn concat_strings_sep_primop_forces_thunked_arguments() {
    assert_eq!(
        eval_string_bytes(
            "let tokens = xs: builtins.filter (t: t != null) xs; \
             in builtins.concatStringsSep \" \" (tokens [ \"a\" null \"b\" ])"
        ),
        b"a b"
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.concatStringsSep \" \" (builtins.attrValues { a = \"x\"; b = \"y\"; })"
        ),
        b"x y"
    );
    assert_eq!(
        eval_string_bytes(
            "let sep = s: s; in builtins.concatStringsSep (sep \", \") [ \"a\" \"b\" ]"
        ),
        b"a, b"
    );
    assert_eq!(
        eval_string_bytes("let xs = [ \"a\" \"b\" ]; in builtins.concatStringsSep \",\" xs"),
        b"a,b"
    );
}

#[test]
fn concat_strings_sep_primop_checks_arguments_left_to_right() {
    let ir = lower("builtins.concatStringsSep 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let separator = args[0];
    let separator_span = ir
        .arena
        .node(separator)
        .expect("separator argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("separator is checked first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: separator,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), separator_span);

    let ir = lower("builtins.concatStringsSep { outPath = \",\"; } [ \"a\" ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let separator = args[0];
    let separator_span = ir
        .arena
        .node(separator)
        .expect("separator argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("separator is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: separator,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), separator_span);

    let ir = lower("builtins.concatStringsSep \",\" 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("second argument must be a list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.concatStringsSep \",\" [ \"a\" 1 ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("list elements must coerce to strings");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);
}

#[test]
fn concat_strings_sep_primop_unions_separator_and_element_contexts() {
    let ir = lower("builtins.concatStringsSep \",\" []");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);

    let separator = ContextElement::opaque_path(b"/nix/store/separator".to_vec())
        .expect("separator context is valid");
    let element = ContextElement::opaque_path(b"/nix/store/element".to_vec())
        .expect("element context is valid");
    let element_value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"elem".to_vec(),
            StringContext::singleton(element.clone()).expect("element context allocates"),
        ))
        .expect("element string allocates");

    let empty = evaluator
        .concat_strings_sep_values(
            ir.root,
            root.span,
            list,
            list_span,
            b",",
            StringContext::singleton(separator.clone()).expect("separator context allocates"),
            &[],
        )
        .expect("empty concatStringsSep evaluates");

    assert_eq!(empty.bytes(), b"");
    assert!(empty.context().contains(&separator));

    let single = evaluator
        .concat_strings_sep_values(
            ir.root,
            root.span,
            list,
            list_span,
            b",",
            StringContext::singleton(separator.clone()).expect("separator context allocates"),
            &[element_value],
        )
        .expect("single-element concatStringsSep evaluates");

    assert_eq!(single.bytes(), b"elem");
    assert!(single.context().contains(&separator));
    assert!(single.context().contains(&element));
}

#[test]
fn substring_primop_slices_coerced_string_bytes() {
    assert_eq!(eval_string_bytes("builtins.substring 1 2 \"abcd\""), b"bc");
    assert_eq!(eval_string_bytes("builtins.substring 10 2 \"abcd\""), b"");
    assert_eq!(
        eval_string_bytes("builtins.substring 1 999 \"abcd\""),
        b"bcd"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 1 (-1) \"abcd\""),
        b"bcd"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 2147483647 1 \"abcd\""),
        b""
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 4294967296 1 \"abcd\""),
        b"a"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 4294967297 1 \"abcd\""),
        b"b"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring (-9223372036854775807) 1 \"abcd\""),
        b"b"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 0 4294967296 \"abcd\""),
        b""
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 0 4294967298 \"abcd\""),
        b"ab"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 0 (-4294967295) \"abcd\""),
        b"a"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 1 2 { outPath = \"abcd\"; }"),
        b"bc"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { substring = start: len: value: \"shadow\"; }; in builtins.substring 1 2 \"abcd\""
        ),
        b"shadow"
    );
}

#[test]
fn substring_primop_checks_arguments_left_to_right() {
    let ir = lower("builtins.substring true (1 / 0) \"abcd\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let start = args[0];
    let start_span = ir.arena.node(start).expect("start exists").span;

    let error = eval_whnf(&ir).expect_err("substring type-checks start first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: start,
            expected: "int",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), start_span);

    let ir = lower("builtins.substring (-1) (1 / 0) \"abcd\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let start = args[0];
    let start_span = ir.arena.node(start).expect("start exists").span;

    let error = eval_whnf(&ir).expect_err("negative start rejects before length");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::NegativeSubstringStart {
            id: start,
            start: -1,
        }
    );
    assert_eq!(error.span(), start_span);

    let ir = lower("builtins.substring 2147483648 1 \"abcd\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let start = args[0];
    let start_span = ir.arena.node(start).expect("start exists").span;

    let error = eval_whnf(&ir).expect_err("oversized start matches Nix start rejection");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::NegativeSubstringStart {
            id: start,
            start: -2_147_483_648,
        }
    );
    assert_eq!(error.span(), start_span);

    let ir = lower("builtins.substring 4294967295 1 \"abcd\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let start = args[0];
    let start_span = ir.arena.node(start).expect("start exists").span;

    let error = eval_whnf(&ir).expect_err("wrapped negative start rejects");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::NegativeSubstringStart {
            id: start,
            start: -1,
        }
    );
    assert_eq!(error.span(), start_span);

    let ir = lower("builtins.substring 1 true (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let len = args[1];
    let len_span = ir.arena.node(len).expect("length exists").span;

    let error = eval_whnf(&ir).expect_err("substring type-checks length before string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: len,
            expected: "int",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), len_span);

    let ir = lower("builtins.substring 1 (-1) (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let string = args[2];
    let string_span = ir.arena.node(string).expect("string exists").span;

    let error = eval_whnf(&ir).expect_err("accepted negative length still forces string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: string }
    );
    assert_eq!(error.span(), string_span);
}

#[test]
fn base_name_and_dir_of_primops_split_path_strings() {
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"/a/b\""), b"b");
    assert_eq!(eval_string_bytes("builtins.dirOf \"/a/b\""), b"/a");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"\""), b"");
    assert_eq!(eval_string_bytes("builtins.dirOf \"\""), b".");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"/\""), b"");
    assert_eq!(eval_string_bytes("builtins.dirOf \"/\""), b"/");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"abc\""), b"abc");
    assert_eq!(eval_string_bytes("builtins.dirOf \"abc\""), b".");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"a/b/c\""), b"c");
    assert_eq!(eval_string_bytes("builtins.dirOf \"a/b/c\""), b"a/b");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"/a/b/\""), b"b");
    assert_eq!(eval_string_bytes("builtins.dirOf \"/a/b/\""), b"/a/b");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"a//\""), b"");
    assert_eq!(eval_string_bytes("builtins.dirOf \"a//\""), b"a");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"a//b\""), b"b");
    assert_eq!(eval_string_bytes("builtins.dirOf \"a//b\""), b"a");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"//a\""), b"a");
    assert_eq!(eval_string_bytes("builtins.dirOf \"//a\""), b"//");
}

#[test]
fn base_name_and_dir_of_primops_coerce_and_shadow() {
    assert_eq!(
        eval_string_bytes("builtins.baseNameOf { outPath = \"/a/b\"; }"),
        b"b"
    );
    assert_eq!(
        eval_string_bytes("builtins.dirOf { __toString = self: \"/a/b\"; }"),
        b"/a"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { baseNameOf = value: \"shadow\"; }; in builtins.baseNameOf \"/a/b\""
        ),
        b"shadow"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { dirOf = value: \"shadow\"; }; in builtins.dirOf \"/a/b\""
        ),
        b"shadow"
    );
}

#[test]
fn parse_drv_name_primop_splits_name_and_version() {
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-1.2\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-1.2\").version"),
        b"1.2"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-bar\").name"),
        b"foo-bar"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-bar\").version"),
        b""
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo--1\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo--1\").version"),
        b"-1"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-.1\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-.1\").version"),
        b".1"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-_1\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-_1\").version"),
        b"_1"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-A-1\").name"),
        b"foo-A"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-A-1\").version"),
        b"1"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-é-1\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-é-1\").version"),
        "é-1".as_bytes()
    );
    assert_eq!(eval_string_bytes("(builtins.parseDrvName \"\").name"), b"");
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-\").name"),
        b"foo-"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-\").version"),
        b""
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"-1\").version"),
        b"1"
    );
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames (builtins.parseDrvName \"foo-1\")"),
        vec![b"name".to_vec(), b"version".to_vec()]
    );
    assert_eq!(
            eval("let builtins = { parseDrvName = x: { name = \"local\"; version = \"\"; }; }; in builtins.parseDrvName \"foo-1\" == { name = \"local\"; version = \"\"; }")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn parse_drv_name_primop_requires_a_string() {
    let ir = lower("builtins.parseDrvName 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("parseDrvName requires a string");

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

#[test]
fn parse_drv_name_primop_rejects_string_context() {
    let ir = lower("builtins.parseDrvName \"foo-1\"");
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
        .expect("parseDrvName argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"foo-1".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let error = evaluator
        .eval_parse_drv_name_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("parseDrvName rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "parseDrvName",
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn split_version_primop_tokenizes_components() {
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"1.2.3\""),
        vec![b"1".to_vec(), b"2".to_vec(), b"3".to_vec()]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"1.0pre2\""),
        vec![b"1".to_vec(), b"0".to_vec(), b"pre".to_vec(), b"2".to_vec()]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"foo-1.2_bar\""),
        vec![
            b"foo".to_vec(),
            b"1".to_vec(),
            b"2".to_vec(),
            b"_bar".to_vec()
        ]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"\""),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \".1..2-\""),
        vec![b"1".to_vec(), b"2".to_vec()]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"1+2~pre\""),
        vec![
            b"1".to_vec(),
            b"+".to_vec(),
            b"2".to_vec(),
            b"~pre".to_vec()
        ]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"pre123post45\""),
        vec![
            b"pre".to_vec(),
            b"123".to_vec(),
            b"post".to_vec(),
            b"45".to_vec()
        ]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"é1β2\""),
        vec![
            "é".as_bytes().to_vec(),
            b"1".to_vec(),
            "β".as_bytes().to_vec(),
            b"2".to_vec()
        ]
    );
    assert_eq!(
            eval("let builtins = { splitVersion = x: [ \"local\" ]; }; in builtins.splitVersion \"1.0\" == [ \"local\" ]")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn split_version_primop_requires_a_string() {
    let ir = lower("builtins.splitVersion 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("splitVersion requires a string");

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

#[test]
fn split_version_primop_rejects_string_context() {
    let ir = lower("builtins.splitVersion \"1.0\"");
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
        .expect("splitVersion argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"1.0".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let error = evaluator
        .eval_split_version_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("splitVersion rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "splitVersion",
        }
    );
    assert_eq!(error.span(), argument_span);
}
