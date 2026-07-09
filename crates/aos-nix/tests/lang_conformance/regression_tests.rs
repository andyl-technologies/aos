//! Focused evaluator regressions mirrored from upstream `lang.sh` cases.

use super::support::*;

#[test]
fn eval_fail_dup_dynamic_attrs_rejects_runtime_duplicates() {
    let source = br#"{
  set = { "${"" + "b"}" = 1; };
  set = { "${"b" + ""}" = 2; };
}"#;

    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    eval_whnf_owned_with_options(&ir, TreeWalkOptions::default())
        .expect("duplicate dynamic key remains latent at top-level WHNF");

    let error = eval_strict_case(source, TreeWalkOptions::default())
        .expect_err("strict eval should force the duplicate dynamic key");
    assert!(
        error.to_string().contains("evaluating strict expression"),
        "{error:?}"
    );
    assert!(
        format!("{error:?}").contains("duplicate attribute key"),
        "{error:?}"
    );
}

#[test]
fn eval_fail_to_json_non_utf8_rejects_invalid_strings() {
    let source = b"builtins.toJSON \"_invalid UTF-8: \xff_\"";

    let error = eval_strict_case(source, TreeWalkOptions::default())
        .expect_err("toJSON should reject non-UTF-8 strings like the upstream lang fixture");
    assert!(
        error.to_string().contains("evaluating strict expression"),
        "{error:?}"
    );
    assert!(
        format!("{error:?}").contains("non-UTF-8 string"),
        "{error:?}"
    );
}

#[test]
fn eval_okay_foldl_strict_keeps_initial_accumulator_lazy() {
    let source = br#"
builtins.foldl'
  (_: x: x)
  (throw "This is never forced")
  [ "but the results of applying op are" 42 ]
"#;

    eval_strict_case(source, TreeWalkOptions::default())
        .expect("foldl' should not force its initial accumulator unconditionally");
    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    let output =
        eval_raw_bytes_with_options(&ir, TreeWalkOptions::default()).expect("source evaluates");
    assert_eq!(output, b"42");
}

#[test]
fn eval_fail_set_override_rejects_non_attrset_overrides() {
    let source = br#"rec { __overrides = 1; }"#;

    let error = eval_strict_case(source, TreeWalkOptions::default())
        .expect_err("__overrides should evaluate to an attrset");
    assert!(
        error.to_string().contains("evaluating strict expression"),
        "{error:?}"
    );
    assert!(format!("{error:?}").contains("__overrides"), "{error:?}");
}

#[test]
fn eval_okay_overrides_replaces_recursive_scope() {
    let source = br#"let
  overrides = { a = 2; b = 3; };
in (rec {
  __overrides = overrides;
  x = a;
  a = 1;
}).x
"#;

    eval_strict_case(source, TreeWalkOptions::default())
        .expect("__overrides should replace the recursive scope value");
    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    let output =
        eval_raw_bytes_with_options(&ir, TreeWalkOptions::default()).expect("source evaluates");
    assert_eq!(output, b"2");
}

#[test]
fn eval_okay_attrs6_applies_overrides_before_dynamic_attrs() {
    let source = br#"rec {
  "${"foo"}" = "bar";
   __overrides = { bar = "qux"; };
}
"#;

    eval_strict_case(source, TreeWalkOptions::default())
        .expect("__overrides should merge before dynamic attrs");
    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    let output =
        eval_raw_bytes_with_options(&ir, TreeWalkOptions::default()).expect("source evaluates");
    assert_eq!(
        output,
        br#"{ __overrides = { bar = "qux"; }; bar = "qux"; foo = "bar"; }"#
    );
}

#[test]
fn eval_okay_eq_derivations_matches_upstream_fixture() {
    let source = br#"let

  drvA1 = derivation { name = "a"; builder = "/foo"; system = "i686-linux"; };
  drvA2 = derivation { name = "a"; builder = "/foo"; system = "i686-linux"; };
  drvA3 = derivation { name = "a"; builder = "/foo"; system = "i686-linux"; } // { dummy = 1; };

  drvC1 = derivation { name = "c"; builder = "/foo"; system = "i686-linux"; };
  drvC2 = derivation { name = "c"; builder = "/bar"; system = "i686-linux"; };

in [ (drvA1 == drvA1) (drvA1 == drvA2) (drvA1 == drvA3) (drvC1 == drvC2) ]
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-eq-derivations.nix", source),
        b"[ true true true false ]"
    );
}

fn eval_raw_fixture(source_name: &[u8], source: &[u8]) -> Vec<u8> {
    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    eval_raw_bytes_with_options_source(
        &ir,
        TreeWalkOptions::default(),
        source_name.to_vec(),
        source.to_vec(),
    )
    .expect("source evaluates")
}

#[test]
fn eval_okay_redefine_builtin_try_eval_catches_search_path_miss() {
    let source = br#"let
  throw = abort "Error!";
in (builtins.tryEval <foobaz>).success
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-redefine-builtin.nix", source),
        b"false"
    );
}

#[test]
fn eval_okay_curpos_reports_current_source_locations() {
    let source = br#"# Bla
let
  x = __curPos;
    y = __curPos;
in [ x.line x.column y.line y.column ]
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-curpos.nix", source),
        b"[ 3 7 4 9 ]"
    );
}

#[test]
fn eval_okay_getattrpos_reports_attr_source_location() {
    let source = br#"let
  as = {
    foo = "bar";
  };
  pos = builtins.unsafeGetAttrPos "foo" as;
in { inherit (pos) column line; file = baseNameOf pos.file; }
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-getattrpos.nix", source),
        br#"{ column = 5; file = "eval-okay-getattrpos.nix"; line = 3; }"#
    );
}

#[test]
fn eval_okay_getattrpos_functionargs_reports_formal_location() {
    let source = br#"let
  fun = { foo }: {};
  pos = builtins.unsafeGetAttrPos "foo" (builtins.functionArgs fun);
in { inherit (pos) column line; file = baseNameOf pos.file; }
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-getattrpos-functionargs.nix", source),
        br#"{ column = 11; file = "eval-okay-getattrpos-functionargs.nix"; line = 2; }"#
    );
}

#[test]
fn eval_okay_inherit_attr_pos_reports_inherit_target_locations() {
    let source = br#"let
  d = 0;
  x = 1;
  y = { inherit d x; };
  z = { inherit (y) d x; };
in
  [
    (builtins.unsafeGetAttrPos "d" y)
    (builtins.unsafeGetAttrPos "x" y)
    (builtins.unsafeGetAttrPos "d" z)
    (builtins.unsafeGetAttrPos "x" z)
  ]
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-inherit-attr-pos.nix", source),
        br#"[ { column = 17; file = "/pwd/lang/eval-okay-inherit-attr-pos.nix"; line = 4; } { column = 19; file = "/pwd/lang/eval-okay-inherit-attr-pos.nix"; line = 4; } { column = 21; file = "/pwd/lang/eval-okay-inherit-attr-pos.nix"; line = 5; } { column = 23; file = "/pwd/lang/eval-okay-inherit-attr-pos.nix"; line = 5; } ]"#
    );
}

#[test]
fn eval_okay_inherit_from_renders_recursive_markers() {
    let source = br#"let
  inherit (builtins.trace "used" { a = 1; b = 2; }) a b;
  x.c = 3;
  y.d = 4;

  merged = {
    inner = {
      inherit (y) d;
    };

    inner = {
      inherit (x) c;
    };
  };
in
  [ a b rec { x.c = []; inherit (x) c; inherit (y) d; __overrides.y.d = []; } merged ]
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-inherit-from.nix", source),
        r#"[ 1 2 { __overrides = { y = { d = [ ]; }; }; c = [ ]; d = 4; x = { c = [ ]; }; y = «repeated»; } { inner = { c = 3; d = 4; }; } ]"#
            .as_bytes()
    );
}

#[test]
fn eval_okay_print_renders_primops_lambdas_and_recursive_lists() {
    let source =
        br#"with builtins; trace [(1+1)] [ null toString (deepSeq "x") (a: a) (let x=[x]; in x) ]
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-print.nix", source),
        "[ null <PRIMOP> <PRIMOP-APP> <LAMBDA> [ [ «repeated» ] ] ]".as_bytes()
    );
}

#[test]
fn eval_fail_derivation_name_rejects_invalid_names() {
    let source = br#"derivation {
  name = "~jiggle~";
  system = "some-system";
  builder = "/dontcare";
}"#;

    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    eval_whnf_owned_with_options(&ir, TreeWalkOptions::default())
        .expect("derivation wrapper stays lazy at WHNF like C++ Nix");

    let error = eval_strict_case(source, TreeWalkOptions::default())
        .expect_err("strict eval should force the invalid derivation name");
    assert!(
        error.to_string().contains("evaluating strict expression"),
        "{error:?}"
    );
    assert!(
        format!("{error:?}").contains("invalid derivation name")
            && format!("{error:?}").contains("contains illegal character '~'"),
        "{error:?}"
    );
}

/// Evaluates a source expression to its raw printed bytes.
fn eval_raw_case(source: &[u8]) -> Vec<u8> {
    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    eval_raw_bytes_with_options(&ir, TreeWalkOptions::default()).expect("source evaluates")
}

// C++ Nix distinguishes the two dynamic attribute key forms: a plain
// `${e}` key whose name evaluates to `null` is silently skipped (the
// `${if cond then "x" else null}` idiom), while a quoted `"${e}"` key is a
// string interpolation that always coerces its fragments — so `null` is a
// "cannot coerce null to a string" error. The quoted form is also always a
// dynamic attribute, even when the interpolant is a string literal.

#[test]
fn eval_fail_quoted_interp_null_attr_key_rejects_null() {
    let source = br#"{ "${null}" = 1; }"#;

    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    eval_whnf_owned_with_options(&ir, TreeWalkOptions::default())
        .expect_err("attrset WHNF forces dynamic key names like C++ Nix");

    let error = eval_strict_case(source, TreeWalkOptions::default())
        .expect_err("quoted-interpolation null key must fail string coercion like C++ Nix");
    assert!(
        format!("{error:?}").contains("expected string, got Null"),
        "{error:?}"
    );
}

#[test]
fn eval_okay_plain_null_dynamic_attr_key_skips_binding() {
    assert_eq!(eval_raw_case(b"{ ${null} = 1; }"), b"{ }");
    assert_eq!(
        eval_raw_case(br#"{ ${if true then null else "x"} = 1; a = 2; }"#),
        b"{ a = 2; }"
    );
}

#[test]
fn eval_okay_plain_null_dynamic_attr_key_keeps_nested_prefix() {
    // The skipped segment still materializes the enclosing static prefix.
    assert_eq!(eval_raw_case(b"{ a.${null} = 1; }"), b"{ a = { }; }");
}

#[test]
fn eval_fail_quoted_interp_null_attr_key_rejects_nested_paths() {
    let error = eval_strict_case(br#"{ a."${null}" = 1; }"#, TreeWalkOptions::default())
        .expect_err("nested quoted-interpolation null key must fail like C++ Nix");
    assert!(
        format!("{error:?}").contains("expected string, got Null"),
        "{error:?}"
    );
}

#[test]
fn eval_fail_plain_dynamic_attr_key_with_string_interp_rejects_null() {
    // `${"${null}"}` is a plain dynamic key whose expression is itself a
    // string interpolation: the inner coercion fails before the null-skip
    // rule can apply, matching C++ Nix.
    let error = eval_strict_case(br#"{ ${"${null}"} = 1; }"#, TreeWalkOptions::default())
        .expect_err("string interpolation inside a plain dynamic key coerces like C++ Nix");
    assert!(
        format!("{error:?}").contains("expected string, got Null"),
        "{error:?}"
    );
}

#[test]
fn eval_okay_quoted_interp_attr_key_still_binds_strings() {
    assert_eq!(eval_raw_case(br#"{ "${"x"}" = 1; }"#), b"{ x = 1; }");
    assert_eq!(
        eval_raw_case(br#"{ "${"a"}${"b"}" = 1; }"#),
        b"{ ab = 1; }"
    );
}

#[test]
fn resolve_fail_quoted_interp_let_binding_is_dynamic() {
    // C++ Nix: "dynamic attributes not allowed in let" — the quoted form is
    // never a static name, even over a string literal.
    let parsed = parse_bytes(br#"let "${"b"}" = 1; in b"#).expect("source parses");
    let error = resolve(parsed).expect_err("quoted-interpolation let binding must be dynamic");
    assert!(
        format!("{error:?}").contains("DynamicLetBinding"),
        "{error:?}"
    );
}

#[test]
fn resolve_fail_quoted_interp_inherit_target_is_dynamic() {
    // C++ Nix: "dynamic attributes not allowed in inherit".
    let parsed = parse_bytes(br#"let x = { a = 1; }; in { inherit (x) "${"a"}"; }"#)
        .expect("source parses");
    let error = resolve(parsed).expect_err("quoted-interpolation inherit target must be dynamic");
    assert!(
        format!("{error:?}").contains("DynamicInheritTarget"),
        "{error:?}"
    );
}

#[test]
fn resolve_fail_quoted_interp_rec_binding_is_not_in_scope() {
    // Dynamic attributes never join the recursive scope in C++ Nix, so the
    // quoted form cannot be referenced even when it folds to a constant.
    let parsed = parse_bytes(br#"rec { "${"a"}" = 1; b = a; }"#).expect("source parses");
    resolve(parsed).expect_err("quoted-interpolation rec binding must not be referencable");
}
