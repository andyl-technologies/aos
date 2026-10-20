//! Explains failed contracts through the same matchers used for admission.
//!
//! These diagnostics do not participate in masking. They report exact clause,
//! expression, identifier and companion counts before showing residual escapes.

use super::super::super::super::{flaky_escape_failures, scrub_comments_and_strings};
use super::super::{
    Contract, compact_code, expression_offsets, identifier_count, mask_contract, source_pattern,
};

/// Reports the exact matcher obligations and residual lexical findings.
pub(super) fn explain(contract: &Contract, code: &str, companions: &[String]) -> Vec<String> {
    let mut findings = Vec::new();
    explain_clauses("local", contract.required, code, &mut findings);

    for (index, (expression, expected)) in contract.expressions.iter().enumerate() {
        let actual = expression_offsets(code, &source_pattern(expression)).len();
        if actual != *expected {
            findings.push(format!(
                "expression[{index}]: expected {expected}, actual {actual}: {expression:?}"
            ));
        }
    }
    for (index, (identifier, expected)) in contract.identifiers.iter().enumerate() {
        let actual = identifier_count(code, identifier);
        if actual != *expected {
            findings.push(format!(
                "identifier[{index}]: expected {expected}, actual {actual}: {identifier:?}"
            ));
        }
    }

    if companions.len() != contract.companions.len() {
        findings.push(format!(
            "companion roster: expected {}, actual {}",
            contract.companions.len(),
            companions.len(),
        ));
    }
    for (binding, source) in contract.companions.iter().zip(companions) {
        let code = scrub_comments_and_strings(source);
        explain_clauses(binding.path, binding.required, &code, &mut findings);
    }

    let masked = mask_contract(contract, code, companions);
    for escape in flaky_escape_failures("unreviewed", "unreviewed", &masked) {
        findings.push(format!("residual: {escape}"));
    }
    findings
}

fn explain_clauses(owner: &str, clauses: &[(&str, usize)], code: &str, findings: &mut Vec<String>) {
    let compact = compact_code(code);
    for (index, (clause, expected)) in clauses.iter().enumerate() {
        let actual = compact.match_indices(&source_pattern(clause)).count();
        if actual != *expected {
            findings.push(format!(
                "{owner} clause[{index}]: expected {expected}, actual {actual}: {clause:?}"
            ));
        }
    }
}
