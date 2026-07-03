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
        name: b"toString",
        source: "builtins.toString 1",
        expected_tag: ValueTag::String,
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
    fn immediate_scalar_numeric_escape_signatures_survive_random_int_inputs(
        left in -1000_i64..=1000,
        right in 1_i64..=1000,
    ) {
        let left = nix_int(left);
        let right = nix_int(right);
        let cases: [(&[u8], String, ValueTag); 7] = [
            (b"sub", format!("builtins.sub {left} {right}"), ValueTag::Int),
            (b"mul", format!("builtins.mul {left} {right}"), ValueTag::Int),
            (b"div", format!("builtins.div {left} {right}"), ValueTag::Int),
            (b"bitAnd", format!("builtins.bitAnd {left} {right}"), ValueTag::Int),
            (b"bitOr", format!("builtins.bitOr {left} {right}"), ValueTag::Int),
            (b"bitXor", format!("builtins.bitXor {left} {right}"), ValueTag::Int),
            (b"lessThan", format!("builtins.lessThan {left} {right}"), ValueTag::Bool),
        ];

        for (name, source, expected_tag) in cases {
            prop_assert_eq!(
                primop_escape_signature(name),
                PrimOpEscapeSignature::ImmediateScalar,
                "{}",
                name_display(name)
            );
            let ir = lower_direct_primop_source(name, &source);
            let outcome = eval_whnf_owned(&ir)
                .map_err(|error| TestCaseError::fail(format!("{error:?}")))?;
            let value = outcome.value();
            prop_assert_eq!(
                value.tag(),
                expected_tag,
                "{}: {}",
                name_display(name),
                source
            );
            prop_assert!(!expected_tag.is_heap(), "{}", name_display(name));
        }
    }
}
