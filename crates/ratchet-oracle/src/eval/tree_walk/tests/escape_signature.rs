//! Tree-walk evaluator tests: semantic escape-signature samples.

use std::collections::BTreeSet;

use proptest::prelude::*;
use ratchet_core::builtins::BUILTINS as CORE_BUILTINS;
use ratchet_core::{PrimOpEscapeSignature, primop_escape_signature};

use super::*;
use crate::value::ValueTag;

#[derive(Clone, Copy, Debug)]
struct SemanticPrimOpSample {
    name: &'static [u8],
    source: &'static str,
    expected_tag: ValueTag,
}

const IMMEDIATE_SCALAR_SEMANTIC_SAMPLES: &[SemanticPrimOpSample] = &[
    SemanticPrimOpSample {
        name: b"isAttrs",
        source: "builtins.isAttrs { a = 1; }",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"isList",
        source: "builtins.isList [ 1 ]",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"isFunction",
        source: "builtins.isFunction (x: x)",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"isString",
        source: r#"builtins.isString "x""#,
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"isInt",
        source: "builtins.isInt 1",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"isFloat",
        source: "builtins.isFloat 1.5",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"isBool",
        source: "builtins.isBool true",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"isNull",
        source: "builtins.isNull null",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"isPath",
        source: "builtins.isPath /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-path",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"length",
        source: "builtins.length [ (1 / 0) ]",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"ceil",
        source: "builtins.ceil 1.2",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"floor",
        source: "builtins.floor 1.8",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"hasContext",
        source: r#"builtins.hasContext "x""#,
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"stringLength",
        source: r#"builtins.stringLength "abc""#,
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"sub",
        source: "builtins.sub 5 3",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"mul",
        source: "builtins.mul 4 3",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"div",
        source: "builtins.div 7 2",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"bitAnd",
        source: "builtins.bitAnd 6 3",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"bitOr",
        source: "builtins.bitOr 4 1",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"bitXor",
        source: "builtins.bitXor 6 3",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"compareVersions",
        source: r#"builtins.compareVersions "1.0" "1.1""#,
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"lessThan",
        source: "builtins.lessThan 1 2",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"all",
        source: "builtins.all (x: x < 4) [ 1 2 3 ]",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"any",
        source: "builtins.any (x: x == 2) [ 1 2 (1 / 0) ]",
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"hasAttr",
        source: r#"builtins.hasAttr "a" { a = 1 / 0; }"#,
        expected_tag: ValueTag::Bool,
    },
    SemanticPrimOpSample {
        name: b"elem",
        source: "builtins.elem 2 [ 1 2 (1 / 0) ]",
        expected_tag: ValueTag::Bool,
    },
];

const CONSERVATIVE_HEAP_SEMANTIC_SAMPLES: &[SemanticPrimOpSample] = &[
    SemanticPrimOpSample {
        name: b"typeOf",
        source: "builtins.typeOf 1",
        expected_tag: ValueTag::String,
    },
    SemanticPrimOpSample {
        name: b"toString",
        source: "builtins.toString 1",
        expected_tag: ValueTag::String,
    },
    SemanticPrimOpSample {
        name: b"toJSON",
        source: "builtins.toJSON { a = 1; }",
        expected_tag: ValueTag::String,
    },
    SemanticPrimOpSample {
        name: b"toXML",
        source: "builtins.toXML { a = 1; }",
        expected_tag: ValueTag::String,
    },
    SemanticPrimOpSample {
        name: b"fromJSON",
        source: r#"builtins.fromJSON "{\"a\":1}""#,
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"fromTOML",
        source: r#"builtins.fromTOML "a = 1""#,
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"seq",
        source: "builtins.seq true [ 1 ]",
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"match",
        source: r#"builtins.match "(a)" "a""#,
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"tryEval",
        source: "builtins.tryEval 1",
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"attrNames",
        source: "builtins.attrNames { b = 2; a = 1; }",
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"attrValues",
        source: "builtins.attrValues { b = 2; a = 1; }",
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"tail",
        source: "builtins.tail [ 1 2 ]",
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"functionArgs",
        source: "builtins.functionArgs ({ a ? 1, b }: a)",
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"getContext",
        source: r#"builtins.getContext "x""#,
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"unsafeDiscardStringContext",
        source: r#"builtins.unsafeDiscardStringContext "x""#,
        expected_tag: ValueTag::String,
    },
    SemanticPrimOpSample {
        name: b"baseNameOf",
        source: r#"builtins.baseNameOf "/a/b""#,
        expected_tag: ValueTag::String,
    },
    SemanticPrimOpSample {
        name: b"dirOf",
        source: r#"builtins.dirOf "/a/b""#,
        expected_tag: ValueTag::String,
    },
    SemanticPrimOpSample {
        name: b"parseDrvName",
        source: r#"builtins.parseDrvName "foo-1.0""#,
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"splitVersion",
        source: r#"builtins.splitVersion "1.2""#,
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"hashString",
        source: r#"builtins.hashString "sha256" "abc""#,
        expected_tag: ValueTag::String,
    },
    SemanticPrimOpSample {
        name: b"concatLists",
        source: "builtins.concatLists [ [ 1 ] [ 2 ] ]",
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"concatMap",
        source: "builtins.concatMap (x: [ x ]) [ 1 2 ]",
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"filter",
        source: "builtins.filter (x: x < 2) [ 1 2 ]",
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"genList",
        source: "builtins.genList (x: x) 2",
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"groupBy",
        source: "builtins.groupBy (x: builtins.toString x) [ 1 2 ]",
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"map",
        source: "builtins.map (x: x + 1) [ 1 ]",
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"partition",
        source: "builtins.partition (x: x < 2) [ 1 2 ]",
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"split",
        source: r#"builtins.split "(a)" "a""#,
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"removeAttrs",
        source: r#"builtins.removeAttrs { a = 1; b = 2; } [ "a" ]"#,
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"intersectAttrs",
        source: "builtins.intersectAttrs { a = 1; } { a = 2; b = 3; }",
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"catAttrs",
        source: r#"builtins.catAttrs "a" [ { a = 1; } { b = 2; } ]"#,
        expected_tag: ValueTag::List,
    },
    SemanticPrimOpSample {
        name: b"concatStringsSep",
        source: r#"builtins.concatStringsSep "," [ "a" "b" ]"#,
        expected_tag: ValueTag::String,
    },
    SemanticPrimOpSample {
        name: b"mapAttrs",
        source: "builtins.mapAttrs (name: value: value) { a = 1; }",
        expected_tag: ValueTag::Attrs,
    },
    SemanticPrimOpSample {
        name: b"zipAttrsWith",
        source: "builtins.zipAttrsWith (name: values: values) [ { a = 1; } { a = 2; } ]",
        expected_tag: ValueTag::Attrs,
    },
];

const CONSERVATIVE_SCALAR_SEMANTIC_SAMPLES: &[SemanticPrimOpSample] = &[
    SemanticPrimOpSample {
        name: b"add",
        source: "builtins.add 1 2",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"seq",
        source: "builtins.seq true 1",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"elemAt",
        source: "builtins.elemAt [ 1 ] 0",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"head",
        source: "builtins.head [ 1 ]",
        expected_tag: ValueTag::Int,
    },
    SemanticPrimOpSample {
        name: b"getAttr",
        source: r#"builtins.getAttr "a" { a = 1; }"#,
        expected_tag: ValueTag::Int,
    },
];

fn name_display(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn nix_int(value: i64) -> String {
    if value < 0 {
        format!("({value})")
    } else {
        value.to_string()
    }
}

fn nix_decimal_tenths(value: i64) -> String {
    let absolute = value.abs();
    let body = if absolute % 10 == 0 {
        (absolute / 10).to_string()
    } else {
        format!("{}.{}", absolute / 10, absolute % 10)
    };
    if value < 0 {
        format!("(-{body})")
    } else {
        body
    }
}

fn simple_ascii_string() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select((b'a'..=b'z').collect::<Vec<_>>()),
        0..16,
    )
    .prop_map(|bytes| String::from_utf8(bytes).expect("ascii bytes are valid utf-8"))
}

fn simple_attr_name() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select((b'a'..=b'y').collect::<Vec<_>>()),
        1..12,
    )
    .prop_map(|bytes| String::from_utf8(bytes).expect("ascii bytes are valid utf-8"))
}

fn sample_name_set(samples: &[SemanticPrimOpSample]) -> BTreeSet<String> {
    samples
        .iter()
        .map(|sample| name_display(sample.name))
        .collect()
}

fn immediate_scalar_signature_name_set() -> BTreeSet<String> {
    CORE_BUILTINS
        .iter()
        .filter(|builtin| {
            primop_escape_signature(builtin.name()) == PrimOpEscapeSignature::ImmediateScalar
        })
        .map(|builtin| name_display(builtin.name()))
        .collect()
}

fn lower_direct_primop_source(name: &[u8], source: &str) -> crate::compile::Ir {
    let ir = lower(source);
    let root = ir.arena.node(ir.root).expect("root node exists");
    assert_eq!(
        root.kind,
        crate::compile::IrKind::PrimOp,
        "{}: {}",
        name_display(name),
        source
    );
    let crate::compile::IrData::PrimOp { symbol, .. } = root.data else {
        panic!(
            "{}: root payload is not a primop: {source}",
            name_display(name)
        );
    };
    let actual = ir
        .symbols
        .resolve(symbol)
        .unwrap_or_else(|| panic!("{}: root primop symbol resolves", name_display(name)));
    assert_eq!(actual, name, "{}: {}", name_display(name), source);
    ir
}

fn assert_semantic_sample_tag(sample: SemanticPrimOpSample) {
    let ir = lower_direct_primop_source(sample.name, sample.source);
    let outcome = eval_whnf_owned(&ir).expect("source evaluates");
    let value = outcome.value();
    assert_eq!(
        value.tag(),
        sample.expected_tag,
        "{}: {}",
        name_display(sample.name),
        sample.source
    );
}

fn assert_immediate_scalar_semantic_sample(sample: SemanticPrimOpSample) {
    assert_eq!(
        primop_escape_signature(sample.name),
        PrimOpEscapeSignature::ImmediateScalar,
        "{}",
        name_display(sample.name)
    );
    assert_semantic_sample_tag(sample);
    assert!(
        !sample.expected_tag.is_heap(),
        "{}",
        name_display(sample.name)
    );
}

#[derive(Clone, Copy, Debug)]
enum ExpectedScalar {
    Bool(bool),
    Int(i64),
}

fn assert_immediate_scalar_value(
    name: &[u8],
    source: &str,
    expected: ExpectedScalar,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(
        primop_escape_signature(name),
        PrimOpEscapeSignature::ImmediateScalar,
        "{}",
        name_display(name)
    );
    let ir = lower_direct_primop_source(name, source);
    let outcome =
        eval_whnf_owned(&ir).map_err(|error| TestCaseError::fail(format!("{error:?}")))?;
    let value = outcome.value();
    match expected {
        ExpectedScalar::Bool(expected) => {
            prop_assert_eq!(
                value.tag(),
                ValueTag::Bool,
                "{}: {}",
                name_display(name),
                source
            );
            prop_assert_eq!(
                value.as_bool(),
                Ok(expected),
                "{}: {}",
                name_display(name),
                source
            );
        }
        ExpectedScalar::Int(expected) => {
            prop_assert_eq!(
                value.tag(),
                ValueTag::Int,
                "{}: {}",
                name_display(name),
                source
            );
            prop_assert_eq!(
                value.as_int(),
                Ok(expected),
                "{}: {}",
                name_display(name),
                source
            );
        }
    }
    prop_assert!(!value.tag().is_heap(), "{}: {}", name_display(name), source);
    Ok(())
}

#[test]
fn immediate_scalar_semantic_samples_cover_signature_surface() {
    let sample_names = sample_name_set(IMMEDIATE_SCALAR_SEMANTIC_SAMPLES);
    assert_eq!(
        sample_names.len(),
        IMMEDIATE_SCALAR_SEMANTIC_SAMPLES.len(),
        "semantic samples must not duplicate builtin names"
    );
    assert_eq!(sample_names, immediate_scalar_signature_name_set());
}

#[test]
fn immediate_scalar_escape_signatures_match_tree_walk_sample_tags() {
    for sample in IMMEDIATE_SCALAR_SEMANTIC_SAMPLES {
        assert_immediate_scalar_semantic_sample(*sample);
    }
}

#[test]
fn conservative_escape_signatures_cover_heap_and_forwarding_samples() {
    for sample in CONSERVATIVE_HEAP_SEMANTIC_SAMPLES {
        assert_eq!(
            primop_escape_signature(sample.name),
            PrimOpEscapeSignature::Conservative,
            "{}",
            name_display(sample.name)
        );
        assert_semantic_sample_tag(*sample);
        assert!(
            sample.expected_tag.is_heap(),
            "{}",
            name_display(sample.name)
        );
    }

    for sample in CONSERVATIVE_SCALAR_SEMANTIC_SAMPLES {
        assert_eq!(
            primop_escape_signature(sample.name),
            PrimOpEscapeSignature::Conservative,
            "{}",
            name_display(sample.name)
        );
        assert_semantic_sample_tag(*sample);
        assert!(
            !sample.expected_tag.is_heap(),
            "{}",
            name_display(sample.name)
        );
    }
}

proptest! {
    #[test]
    fn immediate_scalar_type_predicates_survive_random_inputs(
        selector in 0usize..=17,
        value in -100_i64..=100,
        text in simple_ascii_string(),
    ) {
        let int = nix_int(value);
        let string = format!("{text:?}");
        let (name, source, expected) = match selector {
            0 => (b"isAttrs".as_slice(), "{ a = 1; }".to_owned(), true),
            1 => (b"isAttrs".as_slice(), "[ 1 ]".to_owned(), false),
            2 => (b"isList".as_slice(), "[ 1 ]".to_owned(), true),
            3 => (b"isList".as_slice(), "{ a = 1; }".to_owned(), false),
            4 => (b"isFunction".as_slice(), "(x: x)".to_owned(), true),
            5 => (b"isFunction".as_slice(), int.clone(), false),
            6 => (b"isString".as_slice(), string.clone(), true),
            7 => (b"isString".as_slice(), int.clone(), false),
            8 => (b"isInt".as_slice(), int.clone(), true),
            9 => (b"isInt".as_slice(), "1.5".to_owned(), false),
            10 => (b"isFloat".as_slice(), "1.5".to_owned(), true),
            11 => (b"isFloat".as_slice(), int.clone(), false),
            12 => (b"isBool".as_slice(), "true".to_owned(), true),
            13 => (b"isBool".as_slice(), "null".to_owned(), false),
            14 => (b"isNull".as_slice(), "null".to_owned(), true),
            15 => (b"isNull".as_slice(), "false".to_owned(), false),
            16 => (
                b"isPath".as_slice(),
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-path".to_owned(),
                true,
            ),
            _ => (b"isPath".as_slice(), string, false),
        };
        let source = format!("builtins.{} {source}", name_display(name));
        assert_immediate_scalar_value(name, &source, ExpectedScalar::Bool(expected))?;
    }

    #[test]
    fn immediate_scalar_container_string_and_version_semantics_survive_random_inputs(
        values in prop::collection::vec(-8_i64..=8, 0..8),
        needle in -8_i64..=8,
        threshold in -8_i64..=8,
        text in simple_ascii_string(),
        context_name in simple_attr_name(),
        left_version in 0_u8..=20,
        right_version in 0_u8..=20,
    ) {
        let list_items = values.iter().map(|value| nix_int(*value)).collect::<Vec<_>>().join(" ");
        let list = format!("[ {list_items} ]");
        let needle_source = nix_int(needle);
        let threshold_source = nix_int(threshold);
        let text_source = format!("{text:?}");
        let context_path = format!("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-{context_name}");
        let context_text_source = format!(
            r#"builtins.appendContext {text_source} {{ "{context_path}" = {{ path = true; }}; }}"#
        );
        let compare_versions_expected = match left_version.cmp(&right_version) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };
        let cases: [(&[u8], String, ExpectedScalar); 9] = [
            (
                b"length",
                format!("builtins.length {list}"),
                ExpectedScalar::Int(values.len() as i64),
            ),
            (
                b"stringLength",
                format!("builtins.stringLength {text_source}"),
                ExpectedScalar::Int(text.len() as i64),
            ),
            (
                b"stringLength",
                format!("builtins.stringLength ({context_text_source})"),
                ExpectedScalar::Int(text.len() as i64),
            ),
            (
                b"hasContext",
                format!("builtins.hasContext {text_source}"),
                ExpectedScalar::Bool(false),
            ),
            (
                b"hasContext",
                format!("builtins.hasContext ({context_text_source})"),
                ExpectedScalar::Bool(true),
            ),
            (
                b"compareVersions",
                format!("builtins.compareVersions \"{left_version}\" \"{right_version}\""),
                ExpectedScalar::Int(compare_versions_expected),
            ),
            (
                b"elem",
                format!("builtins.elem {needle_source} {list}"),
                ExpectedScalar::Bool(values.contains(&needle)),
            ),
            (
                b"all",
                format!("builtins.all (x: x < {threshold_source}) {list}"),
                ExpectedScalar::Bool(values.iter().all(|value| *value < threshold)),
            ),
            (
                b"any",
                format!("builtins.any (x: x < {threshold_source}) {list}"),
                ExpectedScalar::Bool(values.iter().any(|value| *value < threshold)),
            ),
        ];

        for (name, source, expected) in cases {
            assert_immediate_scalar_value(name, &source, expected)?;
        }
    }

    #[test]
    fn immediate_scalar_has_attr_semantics_survive_random_names(
        attr_name in simple_attr_name(),
        present in any::<bool>(),
    ) {
        let needle = if present {
            attr_name.clone()
        } else {
            format!("z{attr_name}")
        };
        let attr_name_source = format!("{attr_name:?}");
        let needle_source = format!("{needle:?}");
        let source = format!("builtins.hasAttr {needle_source} {{ {attr_name_source} = 1 / 0; }}");

        assert_immediate_scalar_value(
            b"hasAttr",
            &source,
            ExpectedScalar::Bool(present),
        )?;
    }

    #[test]
    fn immediate_scalar_all_any_semantics_short_circuit_lazy_tails(
        value in -100_i64..=100,
    ) {
        let value_source = nix_int(value);
        let next_source = nix_int(value + 1);
        let cases: [(&[u8], String, ExpectedScalar); 2] = [
            (
                b"all",
                format!("builtins.all (x: x < {value_source}) [ {value_source} (1 / 0) ]"),
                ExpectedScalar::Bool(false),
            ),
            (
                b"any",
                format!("builtins.any (x: x < {next_source}) [ {value_source} (1 / 0) ]"),
                ExpectedScalar::Bool(true),
            ),
        ];

        for (name, source, expected) in cases {
            assert_immediate_scalar_value(name, &source, expected)?;
        }
    }

    #[test]
    fn immediate_scalar_numeric_escape_signatures_survive_random_int_inputs(
        left in -1000_i64..=1000,
        right in 1_i64..=1000,
    ) {
        let left_source = nix_int(left);
        let right_source = nix_int(right);
        let cases: [(&[u8], String, ExpectedScalar); 7] = [
            (
                b"sub",
                format!("builtins.sub {left_source} {right_source}"),
                ExpectedScalar::Int(left - right),
            ),
            (
                b"mul",
                format!("builtins.mul {left_source} {right_source}"),
                ExpectedScalar::Int(left * right),
            ),
            (
                b"div",
                format!("builtins.div {left_source} {right_source}"),
                ExpectedScalar::Int(left / right),
            ),
            (
                b"bitAnd",
                format!("builtins.bitAnd {left_source} {right_source}"),
                ExpectedScalar::Int(left & right),
            ),
            (
                b"bitOr",
                format!("builtins.bitOr {left_source} {right_source}"),
                ExpectedScalar::Int(left | right),
            ),
            (
                b"bitXor",
                format!("builtins.bitXor {left_source} {right_source}"),
                ExpectedScalar::Int(left ^ right),
            ),
            (
                b"lessThan",
                format!("builtins.lessThan {left_source} {right_source}"),
                ExpectedScalar::Bool(left < right),
            ),
        ];

        for (name, source, expected) in cases {
            assert_immediate_scalar_value(name, &source, expected)?;
        }
    }

    #[test]
    fn immediate_scalar_rounding_escape_signatures_survive_random_tenths(
        tenths in -10_000_i64..=10_000,
    ) {
        let value = nix_decimal_tenths(tenths);
        let cases: [(&[u8], String, ExpectedScalar); 2] = [
            (
                b"ceil",
                format!("builtins.ceil {value}"),
                ExpectedScalar::Int(-((-tenths).div_euclid(10))),
            ),
            (
                b"floor",
                format!("builtins.floor {value}"),
                ExpectedScalar::Int(tenths.div_euclid(10)),
            ),
        ];

        for (name, source, expected) in cases {
            assert_immediate_scalar_value(name, &source, expected)?;
        }
    }
}
