//! Phase 4 Chunk E static-update demand and assembly tests.

use super::*;
use crate::ir::{LambdaAttrKeys, LambdaDemand};
use crate::syntax::BinOpKind;

fn unwrap_thunk(ir: &Ir, mut id: IrId) -> IrId {
    loop {
        match node(ir, id) {
            IrNode {
                kind: IrKind::ThunkAlloc,
                data: IrData::Node(body),
                ..
            } => id = *body,
            _ => return id,
        }
    }
}

fn update_operands(ir: &Ir, id: IrId) -> (IrId, IrId) {
    let id = unwrap_thunk(ir, id);
    let IrData::Binary {
        op: BinOpKind::Update,
        lhs,
        rhs,
    } = node(ir, id).data
    else {
        panic!("update payload expected");
    };
    (lhs, rhs)
}

fn static_binding_values(ir: &Ir, id: IrId) -> Vec<(IrId, Vec<u8>)> {
    let id = unwrap_thunk(ir, id);
    let IrData::AttrSet { bindings, .. } = node(ir, id).data else {
        panic!("attrset payload expected");
    };
    let start = bindings.start as usize;
    let end = start + bindings.len();
    ir.bindings[start..end]
        .iter()
        .filter_map(|binding| match binding.key {
            IrAttrPathSegment::Static(key) => Some((
                binding.value,
                ir.symbols.resolve(key).expect("key resolves").to_vec(),
            )),
            IrAttrPathSegment::Dynamic(_) => None,
        })
        .collect()
}

fn value_for(entries: &[(IrId, Vec<u8>)], key: &[u8]) -> IrId {
    entries
        .iter()
        .find(|(_, entry)| entry == key)
        .map(|(value, _)| *value)
        .unwrap_or_else(|| panic!("binding {:?} exists", String::from_utf8_lossy(key)))
}

fn derivation_strict_argument(ir: &Ir) -> IrId {
    let IrData::DialectNode { argument, .. } = node(ir, ir.root).data else {
        panic!("dialect-node payload expected");
    };
    argument
}

fn annotate_all(source: &str) -> Ir {
    let mut ir = lowered(source);
    annotate_ir(&mut ir).expect("complete analysis succeeds");
    ir
}

fn annotate_all_with_derivation_op(source: &str) -> Ir {
    let mut ir = lowered_with_derivation_op(source);
    annotate_ir(&mut ir).expect("complete analysis succeeds");
    ir
}

fn root_lambda_pattern(ir: &Ir) -> IrId {
    let IrData::Lambda { pattern, .. } = node(ir, ir.root).data else {
        panic!("root lambda payload expected");
    };
    pattern
}

#[test]
fn derivation_strict_static_update_seeds_only_surviving_bindings() {
    let ir = annotate_with_derivation_op(
        r#"builtins.derivationStrict (
          {
            name = "left" + "name";
            builder = [ (1 / 0) ];
            leftLazy = 1 / 0;
          }
          // {
            name = "right" + "name";
            rightTotal = [ (1 / 0) ];
            rightLazy = 1 / 0;
          }
        )"#,
    );
    let (lhs, rhs) = update_operands(&ir, derivation_strict_argument(&ir));
    let left = static_binding_values(&ir, lhs);
    let right = static_binding_values(&ir, rhs);

    let shadowed_name = value_for(&left, b"name");
    assert_eq!(strictness(&ir, shadowed_name), Strictness::Unknown);
    assert!(!ir.facts.assembly_eager(shadowed_name));

    let builder = value_for(&left, b"builder");
    assert_eq!(strictness(&ir, builder), Strictness::Demanded);
    assert!(ir.facts.assembly_eager(builder));

    let left_lazy = value_for(&left, b"leftLazy");
    assert_eq!(strictness(&ir, left_lazy), Strictness::Demanded);
    assert!(!ir.facts.assembly_eager(left_lazy));

    let surviving_name = value_for(&right, b"name");
    assert_eq!(
        strictness(&ir, surviving_name),
        Strictness::DemandedBeforeEffect
    );
    assert!(ir.facts.assembly_eager(surviving_name));

    let right_total = value_for(&right, b"rightTotal");
    assert_eq!(strictness(&ir, right_total), Strictness::Demanded);
    assert!(ir.facts.assembly_eager(right_total));

    let right_lazy = value_for(&right, b"rightLazy");
    assert_eq!(strictness(&ir, right_lazy), Strictness::Demanded);
    assert!(!ir.facts.assembly_eager(right_lazy));
}

#[test]
fn derivation_strict_nested_static_updates_apply_right_bias_transitively() {
    let ir = annotate_with_derivation_op(
        r#"builtins.derivationStrict (
          ({ name = "first" + "name"; keep = [ 1 ]; } //
           { name = "second" + "name"; shadow = [ 2 ]; }) //
          { name = "third" + "name"; shadow = 1 / 0; }
        )"#,
    );
    let (prefix, last) = update_operands(&ir, derivation_strict_argument(&ir));
    let (first, second) = update_operands(&ir, prefix);
    let first = static_binding_values(&ir, first);
    let second = static_binding_values(&ir, second);
    let last = static_binding_values(&ir, last);

    for shadowed in [
        value_for(&first, b"name"),
        value_for(&second, b"name"),
        value_for(&second, b"shadow"),
    ] {
        assert_eq!(strictness(&ir, shadowed), Strictness::Unknown);
        assert!(!ir.facts.assembly_eager(shadowed));
    }

    let keep = value_for(&first, b"keep");
    assert_eq!(strictness(&ir, keep), Strictness::Demanded);
    assert!(ir.facts.assembly_eager(keep));

    let name = value_for(&last, b"name");
    assert_eq!(strictness(&ir, name), Strictness::DemandedBeforeEffect);
    assert!(ir.facts.assembly_eager(name));

    let shadow = value_for(&last, b"shadow");
    assert_eq!(strictness(&ir, shadow), Strictness::Demanded);
    assert!(!ir.facts.assembly_eager(shadow));
}

#[test]
fn derivation_wrapper_static_update_licenses_only_surviving_totals() {
    let ir = annotate(
        r#"builtins.derivation (
          { name = "left" + "name"; keep = [ (1 / 0) ]; } //
          { name = "right" + "name"; lazy = 1 / 0; }
        )"#,
    );
    let argument = primop_args(&ir, ir.root)[0];
    let (lhs, rhs) = update_operands(&ir, argument);
    let left = static_binding_values(&ir, lhs);
    let right = static_binding_values(&ir, rhs);

    let shadowed_name = value_for(&left, b"name");
    assert_eq!(strictness(&ir, shadowed_name), Strictness::Unknown);
    assert!(!ir.facts.assembly_eager(shadowed_name));

    let keep = value_for(&left, b"keep");
    assert_eq!(strictness(&ir, keep), Strictness::Unknown);
    assert!(ir.facts.assembly_eager(keep));

    for lazy in [value_for(&right, b"name"), value_for(&right, b"lazy")] {
        assert_eq!(strictness(&ir, lazy), Strictness::Unknown);
        assert!(!ir.facts.assembly_eager(lazy));
    }
}

#[test]
fn derivation_strict_update_declines_if_either_operand_is_not_static() {
    let ir = annotate_with_derivation_op(
        r#"builtins.derivationStrict (
          { name = "left" + "name"; keep = [ 1 ]; } //
          { name = "right" + "name"; ${"dy" + "namic"} = [ 2 ]; }
        )"#,
    );
    let (lhs, rhs) = update_operands(&ir, derivation_strict_argument(&ir));
    let entries = static_binding_values(&ir, lhs)
        .into_iter()
        .chain(static_binding_values(&ir, rhs))
        .collect::<Vec<_>>();

    for (value, _) in entries {
        assert_eq!(strictness(&ir, value), Strictness::Unknown);
        assert!(!ir.facts.assembly_eager(value));
    }
}

#[test]
fn chunk_e_persists_structural_totality_for_cross_module_assembly() {
    let ir = annotate_all("{ total = [ (1 / 0) ]; effectful = 1 / 0; }");
    let entries = static_binding_values(&ir, ir.root);

    assert!(ir.facts.structurally_total(value_for(&entries, b"total")));
    assert!(
        !ir.facts
            .structurally_total(value_for(&entries, b"effectful"))
    );
}

#[test]
fn chunk_e_summarizes_mkderivation_style_open_argument_keys() {
    let ir = annotate_all(
        r#"args @ { name, ignored ? null, ... }:
          builtins.derivation (
            { inherit name; builder = "b"; system = "x"; } //
            builtins.removeAttrs args [ "ignored" ]
          )"#,
    );
    let pattern = root_lambda_pattern(&ir);
    let summary = ir
        .facts
        .lambda_call_summary(pattern)
        .expect("lambda call summary exists");

    assert_eq!(
        summary.argument_demand,
        LambdaDemand::Unconditional(Strictness::DemandedBeforeEffect)
    );
    let attr = summary
        .attr_values
        .iter()
        .find(|attr| matches!(attr.keys, LambdaAttrKeys::AllExcept(_)))
        .expect("open-key derivation summary exists");
    assert_eq!(
        attr.demand,
        LambdaDemand::IfResultForced(Strictness::Demanded)
    );
    let excluded = attr
        .keys
        .symbols()
        .iter()
        .map(|symbol| {
            ir.symbols
                .resolve(*symbol)
                .expect("summary symbol resolves")
        })
        .collect::<Vec<_>>();
    assert_eq!(excluded, [b"ignored".as_slice()]);
}

#[test]
fn chunk_e_summarizes_direct_derivation_strict_alias_demand() {
    let ir = annotate_all_with_derivation_op(
        r#"args @ { ... }:
          builtins.derivationStrict ({ name = "n"; builder = "b"; } // args)"#,
    );
    let summary = ir
        .facts
        .lambda_call_summary(root_lambda_pattern(&ir))
        .expect("lambda call summary exists");
    let attr = summary
        .attr_values
        .first()
        .expect("direct derivation alias summary exists");

    assert_eq!(
        attr.demand,
        LambdaDemand::Unconditional(Strictness::Demanded)
    );
    assert!(matches!(attr.keys, LambdaAttrKeys::AllExcept(ref keys) if keys.is_empty()));
}

#[test]
fn chunk_e_declines_simple_formals_without_attribute_key_contracts() {
    let ir = annotate_all("value: value");

    assert!(
        ir.facts
            .lambda_call_summary(root_lambda_pattern(&ir))
            .is_none()
    );
}

#[test]
fn chunk_e_recursive_summary_aliases_fail_closed() {
    let ir = annotate_all("args @ { ... }: let loop = loop; in loop");
    let summary = ir
        .facts
        .lambda_call_summary(root_lambda_pattern(&ir))
        .expect("recursive lambda summary exists");

    assert_eq!(
        summary.formals[0].demand,
        LambdaDemand::IfResultForced(Strictness::Unknown)
    );
}

#[test]
fn chunk_e_formal_cardinality_proves_only_exact_lexical_absence() {
    let absent = annotate_all("{ x ? 1 }: 0");
    let absent_summary = absent
        .facts
        .lambda_call_summary(root_lambda_pattern(&absent))
        .expect("absent formal summary exists");
    assert_eq!(absent_summary.formals[0].cardinality, Cardinality::Absent);

    let default_reference = annotate_all("{ x ? 1, y ? x }: y");
    let default_summary = default_reference
        .facts
        .lambda_call_summary(root_lambda_pattern(&default_reference))
        .expect("default-reference summary exists");
    assert_eq!(
        default_summary.formals[0].cardinality,
        Cardinality::Many,
        "a sibling default reference keeps the formal present"
    );
    assert_eq!(default_summary.formals[1].cardinality, Cardinality::Many);

    let nested_capture = annotate_all("{ x ? 1 }: (y: x)");
    let capture_summary = nested_capture
        .facts
        .lambda_call_summary(root_lambda_pattern(&nested_capture))
        .expect("capture summary exists");
    assert_eq!(
        capture_summary.formals[0].cardinality,
        Cardinality::Many,
        "a nested closure capture keeps the formal present"
    );
}
