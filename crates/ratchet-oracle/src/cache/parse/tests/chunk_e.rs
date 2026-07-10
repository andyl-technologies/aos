//! Phase 4 Chunk E persisted fact-format tests.

use super::*;

#[test]
fn chunk_e_fact_artifact_roundtrips_totality_and_lambda_summaries() {
    let mut facts = IrFacts::conservative(4);
    facts.set_structurally_total(IrId::new(1), true);
    facts.set_structurally_total(IrId::new(3), true);
    facts.set_lambda_call_summaries(vec![LambdaCallSummary {
        pattern: IrId::new(2),
        argument_demand: LambdaDemand::Unconditional(Strictness::DemandedBeforeEffect),
        argument_escape: Escape::NoEscape,
        formals: vec![
            LambdaFormalSummary {
                demand: LambdaDemand::IfResultForced(Strictness::Demanded),
                escape: Escape::Escapes,
            },
            LambdaFormalSummary {
                demand: LambdaDemand::Unconditional(Strictness::DemandedBeforeEffect),
                escape: Escape::NoEscape,
            },
        ]
        .into_boxed_slice(),
        attr_values: vec![
            LambdaAttrValueSummary {
                keys: LambdaAttrKeys::Only(
                    vec![Symbol::new(7), Symbol::new(11)].into_boxed_slice(),
                ),
                demand: LambdaDemand::Unconditional(Strictness::Demanded),
                escape: Escape::NoEscape,
            },
            LambdaAttrValueSummary {
                keys: LambdaAttrKeys::AllExcept(vec![Symbol::new(13)].into_boxed_slice()),
                demand: LambdaDemand::IfResultForced(Strictness::Demanded),
                escape: Escape::Escapes,
            },
        ]
        .into_boxed_slice(),
    }]);
    let fingerprint = test_lowered_ir_fingerprint(b"chunk-e-facts");

    let encoded = encode_ir_facts(&facts, fingerprint, crate::compile::IR_ANALYSIS_VERSION)
        .expect("Chunk E facts encode");
    let (decoded, version) =
        decode_ir_facts(&encoded, 4, fingerprint).expect("Chunk E facts decode");

    assert_eq!(version, crate::compile::IR_ANALYSIS_VERSION);
    assert_eq!(decoded, facts);
    assert!(!decoded.structurally_total(IrId::new(0)));
    assert!(decoded.structurally_total(IrId::new(1)));
    assert_eq!(
        decoded
            .lambda_call_summary(IrId::new(2))
            .expect("summary survives")
            .attr_values
            .len(),
        2
    );
}

#[test]
fn chunk_e_validator_rejects_malformed_lambda_summary_contracts() {
    let mut wrong_count = lowered_ir_for_source("{ value }: value");
    crate::compile::annotate_ir(&mut wrong_count).expect("analysis succeeds");
    wrong_count
        .facts
        .lambda_call_summaries_mut()
        .first_mut()
        .expect("summary exists")
        .formals = Box::new([]);
    let error =
        validate_lowered_ir_artifact(&wrong_count).expect_err("formal-count mismatch is rejected");
    assert!(error.contains("formal count"), "{error}");

    let mut invalid_symbol = lowered_ir_for_source("args @ { ... }: args");
    crate::compile::annotate_ir(&mut invalid_symbol).expect("analysis succeeds");
    invalid_symbol
        .facts
        .lambda_call_summaries_mut()
        .first_mut()
        .expect("summary exists")
        .attr_values = vec![LambdaAttrValueSummary {
        keys: LambdaAttrKeys::Only(vec![Symbol::new(u32::MAX)].into_boxed_slice()),
        demand: LambdaDemand::Unconditional(Strictness::Demanded),
        escape: Escape::Escapes,
    }]
    .into_boxed_slice();
    let error = validate_lowered_ir_artifact(&invalid_symbol)
        .expect_err("out-of-range summary symbol is rejected");
    assert!(error.contains("symbol id"), "{error}");

    let mut missing_alias = lowered_ir_for_source("{ value, ... }: value");
    crate::compile::annotate_ir(&mut missing_alias).expect("analysis succeeds");
    missing_alias
        .facts
        .lambda_call_summaries_mut()
        .first_mut()
        .expect("summary exists")
        .attr_values = vec![LambdaAttrValueSummary {
        keys: LambdaAttrKeys::AllExcept(Box::new([])),
        demand: LambdaDemand::Unconditional(Strictness::Demanded),
        escape: Escape::Escapes,
    }]
    .into_boxed_slice();
    let error = validate_lowered_ir_artifact(&missing_alias)
        .expect_err("attribute rules without an alias are rejected");
    assert!(error.contains("formal-set alias"), "{error}");
}

#[test]
fn chunk_e_parse_entry_ignores_structurally_invalid_fact_sidecar() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"x: x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("callee.nix".to_owned()))
        .expect("source parses");
    let entry = parsed.entry;
    let (base_ir, _) = entry.read_ir().expect("base IR reads");
    let mut facts = IrFacts::conservative(base_ir.arena.nodes().len());
    facts.set_lambda_call_summaries(vec![LambdaCallSummary {
        pattern: base_ir.root,
        argument_demand: LambdaDemand::Unconditional(Strictness::Demanded),
        argument_escape: Escape::Escapes,
        formals: Box::new([]),
        attr_values: Box::new([]),
    }]);
    let encoded = encode_ir_facts(
        &facts,
        lowered_ir_fingerprint(&base_ir).expect("IR fingerprint computes"),
        crate::compile::IR_ANALYSIS_VERSION,
    )
    .expect("invalid structural facts still encode");
    fs::write(entry.facts_path(), encoded).expect("fact sidecar writes");

    let (loaded, facts_current) = entry.read_ir().expect("IR with sidecar reads");

    assert!(!facts_current);
    assert!(loaded.facts.lambda_call_summaries().is_empty());
    assert!(
        loaded
            .facts
            .as_slice()
            .iter()
            .all(|facts| *facts == ExprFacts::conservative())
    );

    let _ = fs::remove_dir_all(root);
}
