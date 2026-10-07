//! Bounded deterministic work records emitted after performance timing windows.
//!
//! Physical ownership, elapsed time, and sample identity belong to separate
//! provenance. These records retain the original authenticated semantic values;
//! they never normalize console bytes or substitute expected work constants.

use serde_json::{Value, json};

use super::evidence::ContinuationEvidence;

const MAX_WORK_RECORD_BYTES: usize = 1024 * 1024;

/// Projects actual accepted continuation identities and their ordered events.
fn continuation(evidence: &ContinuationEvidence) -> Value {
    let outcomes: Vec<Value> = evidence
        .outcomes
        .iter()
        .map(|outcome| {
            assert!(outcome.event_log_entries.iter().all(|entry| entry.has_valid_content_hash()));
            json!({
                "configuration": outcome.configuration.id().to_hex(),
                "frontier_ticks": outcome.frontier.ticks,
                "advanced_node": outcome.advanced_node,
                "event_log_entries": outcome.event_log_entries.iter().map(|entry| json!({
                    "content_hash": entry.content_hash().to_hex(),
                    "canonical_material_bytes": entry.canonical_material_len(),
                })).collect::<Vec<_>>(),
                "segment_bytes": outcome.event_log_segment_bytes.len(),
                "segment_content": crucible::model::ContentHash::from_bytes(&outcome.event_log_segment_bytes).to_hex(),
                "event_log_segment_hash": outcome.event_log_segment_hash,
                "event_log_offset": outcome.event_log_offset,
            })
        })
        .collect();
    let fingerprints: Vec<Value> = evidence
        .fingerprints
        .values()
        .map(|sample| {
            json!({
                "node": sample.node,
                "at_ticks": sample.at.ticks,
                "fingerprint": sample.fingerprint.hash.to_hex(),
            })
        })
        .collect();

    json!({
        "reply_events": evidence.reply_events.iter().map(|entry| {
            assert!(entry.has_valid_content_hash());
            json!({
                "content_hash": entry.content_hash().to_hex(),
                "canonical_material_bytes": entry.canonical_material_len(),
            })
        }).collect::<Vec<_>>(),
        "outcomes": outcomes,
        "fingerprints": fingerprints,
        "resolved_effect_trace": evidence.fault_evidence.resolved_effect_trace,
        "locked_effect_trace": evidence.fault_evidence.locked_effect_trace,
    })
}

/// Encodes one bounded record from the original planner and accepted guests.
fn encode(
    index: usize,
    planner: Value,
    hot: &ContinuationEvidence,
    exact: &ContinuationEvidence,
) -> Vec<u8> {
    let record = json!({
        "schema": "crucible.campaign-performance.work.v2",
        "corpus": index,
        "planner": planner,
        "hot": continuation(hot),
        "exact": continuation(exact),
    });
    let bytes = serde_json::to_vec(&record).expect("encode authentic performance work");
    assert!(
        bytes.len() <= MAX_WORK_RECORD_BYTES,
        "performance work record exceeds bound"
    );
    bytes
}

/// Emits only a complete record after its serialized byte bound is checked.
pub(super) fn emit(
    index: usize,
    planner: Value,
    hot: &ContinuationEvidence,
    exact: &ContinuationEvidence,
) {
    let bytes = encode(index, planner, hot, exact);
    let text = std::str::from_utf8(&bytes).expect("JSON work record is UTF-8");
    println!("corpus_{index}_campaign_work_json={text}");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;

    use crucible::{Configuration, EventLogOffset, ScenarioDefForm, VirtualTime};
    use crucible_api::ProductionFaultEvidenceSnapshot;

    use super::*;

    fn evidence(frontier: u64) -> Result<ContinuationEvidence, Box<dyn Error>> {
        let source = ScenarioDefForm::from_canonical_toml(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/crucible/fixtures/e2e-determinism.scenario.toml"
        )))?;
        Ok(ContinuationEvidence {
            reply_events: Vec::new(),
            outcomes: vec![crucible::QuantumOutcome {
                configuration: Configuration::genesis(source.scenario_def()),
                frontier: VirtualTime { ticks: frontier },
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                discovered_choices: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: EventLogOffset::default(),
                scheduler_quiescence: None,
            }],
            fingerprints: BTreeMap::new(),
            fault_evidence: ProductionFaultEvidenceSnapshot {
                frontier: VirtualTime { ticks: frontier },
                resolved_effect_trace: None,
                locked_effect_trace: None,
                emitted_events: Vec::new(),
                network_outages: Vec::new(),
                network_queues: Vec::new(),
                block_devices: Vec::new(),
                nodes: Vec::new(),
            },
        })
    }

    #[test]
    fn work_projection_retains_canonical_configuration_and_virtual_work()
    -> Result<(), Box<dyn Error>> {
        let original = evidence(1000)?;
        let repeated = evidence(1000)?;
        let different = evidence(1001)?;

        assert_eq!(continuation(&original), continuation(&repeated));
        assert_ne!(continuation(&original), continuation(&different));
        assert_eq!(
            continuation(&original)["outcomes"][0]["configuration"],
            original.outcomes[0].configuration.id().to_hex(),
        );
        Ok(())
    }

    #[test]
    #[should_panic(expected = "performance work record exceeds bound")]
    fn oversized_work_record_is_refused_before_emission() {
        let original = evidence(1000).expect("parse actual scenario fixture");
        let oversized = json!({"retained_control_payload": "x".repeat(MAX_WORK_RECORD_BYTES)});
        let _ = encode(0, oversized, &original, &original);
    }

    #[test]
    fn work_projection_preserves_original_segment_bytes() -> Result<(), Box<dyn Error>> {
        let mut original = evidence(1000)?;
        original.outcomes[0].event_log_segment_bytes = vec![0, 0xff, b'\n'];
        let projected = continuation(&original);

        assert_eq!(projected["outcomes"][0]["segment_bytes"], 3);
        assert_eq!(
            projected["outcomes"][0]["segment_content"],
            crucible::model::ContentHash::from_bytes(&[0, 255, 10]).to_hex(),
        );
        original.outcomes[0].event_log_segment_bytes.push(0);
        assert_ne!(projected, continuation(&original));
        Ok(())
    }
}
