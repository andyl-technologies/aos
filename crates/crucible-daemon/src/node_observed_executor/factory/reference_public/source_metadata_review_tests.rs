//! Adversarial data checks against an actual actor's four source review witnesses.

use super::*;

/// Checks full private authority recomputation against self-consistent tampering.
///
/// # Errors
/// Refuses missing genuine witnesses or a mutation that does not reach the
/// exact source-authentication refusal.
pub(in crate::node_observed_executor::factory::reference_public) fn verify(
    original: &mut CandidateHarnessResult,
) -> Result<(), QualificationError> {
    super::super::issuer::authenticate_source_reviews_for_test(original)?;
    let genuine = original
        .take_source_reviews_for_test()
        .ok_or(refused("actual original source reviews absent"))?;
    let trial = (|| {
        // These are explicitly intercepted recorder failures in a data model,
        // not claims that the native provider violated a semantic property.
        for unwound in [false, true] {
            let calls = std::cell::Cell::new(0);
            let attempted = original_attempt::<()>(|| {
                calls.set(calls.get() + 1);
                if unwound {
                    std::panic::resume_unwind(Box::new("model original inspection unwind"));
                }
                Err(refused("model original inspection failure"))
            });
            let failure = attempted
                .err()
                .ok_or(refused("model original failure was lost"))?;
            if calls.get() != 1 || failure.unwound != unwound {
                return Err(refused("model original inspection was retried"));
            }
            let predecessor = super::super::issuer::issue_native_report(original)?;
            let failed = if unwound {
                // Retain the completed collection too when later authentication
                // becomes unknown. These observations cannot receive Pass credit.
                let failed = SourceMetadataReviews::failed(
                    original,
                    &predecessor,
                    &failure.diagnostic,
                    true,
                    Some(&genuine),
                )?;
                for (reference, bytes) in genuine.objects() {
                    if !failed
                        .objects()
                        .any(|(retained, body)| retained == reference && body == bytes)
                    {
                        return Err(refused(
                            "prior completed source observations were discarded",
                        ));
                    }
                }
                failed
            } else {
                SourceMetadataReviews::failure_objects(original, &predecessor, failure)?
            };
            original.replace_source_reviews_for_test(failed);
            let first = super::super::issuer::issue_report(original)?;
            let second = super::super::issuer::issue_report(original)?;
            if first.reference() != second.reference()
                || first.bytes() != second.bytes()
                || calls.get() != 1
            {
                return Err(refused(
                    "failed original bytes changed during publication preparation",
                ));
            }
            let claim: crate::node_qualification::QualificationClaim =
                serde_json::from_value(canonical::parse_json(first.bytes(), 4 * 1024 * 1024)?)
                    .map_err(crucible_node_contract::ContractError::from)?;
            if claim
                .requirements
                .iter()
                .filter(|row| {
                    row.disposition == crate::node_qualification::RequirementDisposition::Failed
                })
                .count()
                != 4
                || claim.requirements.iter().any(|row| {
                    row.disposition == crate::node_qualification::RequirementDisposition::Passed
                })
            {
                return Err(refused(
                    "original failed source inspection became passing evidence",
                ));
            }
            original.take_source_reviews_for_test();
        }
        for mutation in [
            "inspector",
            "report",
            "unit",
            "negative-population",
            "artifact-table",
            "plan",
            "case-kind",
        ] {
            let mut changed = SourceMetadataReviews {
                predecessor: genuine.predecessor.clone(),
                predecessor_bytes: genuine.predecessor_bytes.clone(),
                predecessor_objects: genuine.predecessor_objects.clone(),
                aggregate: genuine.aggregate.clone(),
                aggregate_bytes: genuine.aggregate_bytes.clone(),
                results: genuine.results.clone(),
                failure: genuine.failure.clone(),
            };
            let false_ref =
                canonical::content_ref(b"source-owned rehashed hostile witness", "text/plain")?;
            let false_ref = serde_json::to_value(false_ref)
                .map_err(crucible_node_contract::ContractError::from)?;
            let mut aggregate =
                canonical::parse_json(&changed.aggregate_bytes, MAXIMUM_REVIEW_BYTES)?;
            match mutation {
                "inspector" => aggregate["source_inspector"] = false_ref,
                "report" => aggregate["native_predecessor"] = false_ref,
                "unit" => aggregate["unit"]["environment"] = false_ref,
                "plan" => aggregate["plan"] = false_ref,
                "negative-population" => {
                    aggregate["metadata_inspection"]["counterfactuals"]
                        .as_array_mut()
                        .ok_or(refused("actual negative population absent"))?
                        .pop();
                }
                "artifact-table" => {
                    aggregate["artifact_controls"]["observed"]
                        .as_array_mut()
                        .ok_or(refused("actual artifact table absent"))?
                        .pop();
                }
                "case-kind" => {}
                _ => return Err(refused("unplanned source review mutation")),
            }
            changed.aggregate_bytes = canonical::canonical_json(&aggregate)?;
            changed.aggregate =
                canonical::content_ref(&changed.aggregate_bytes, "application/json")?;
            // Rehash every dependent case result too: integrity alone must not
            // turn this altered data into the actual source-issued population.
            for (reference, bytes) in changed.results.values_mut() {
                let mut value = canonical::parse_json(bytes, 1024 * 1024)?;
                value["source_reviews"] = serde_json::to_value(&changed.aggregate)
                    .map_err(crucible_node_contract::ContractError::from)?;
                if mutation == "case-kind" {
                    value["case_kind"] = json!("realized_provider");
                }
                *bytes = canonical::canonical_json(&value)?;
                *reference = canonical::content_ref(bytes, "application/json")?;
            }
            original.replace_source_reviews_for_test(changed);
            let result = super::super::issuer::authenticate_source_reviews_for_test(original);
            original.take_source_reviews_for_test();
            if !matches!(
                result,
                Err(QualificationError::Refused(
                    "original source metadata review witness changed"
                ))
            ) {
                return Err(refused(
                    "changed source review did not reach exact original authority refusal",
                ));
            }
        }
        Ok(())
    })();
    original.replace_source_reviews_for_test(genuine);
    trial
}
