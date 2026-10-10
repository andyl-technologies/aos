//! Synthetic closed-codec controls; these receipts confer no native authority.

use crucible_node_contract::{Phase, Position, U64};
use serde_json::json;

use super::*;

fn receipt(schema: &str) -> Result<InputPayload, TranscriptError> {
    let source =
        canonical::content_ref(b"signed source data", "application/json").map_err(invalid)?;
    let proof =
        canonical::content_ref(b"original ACK data", "application/json").map_err(invalid)?;
    let inventory = canonical::content_ref(b"original ordered input data", "application/json")
        .map_err(invalid)?;
    let world = canonical::content_ref(b"world data", "application/json")
        .map_err(invalid)?
        .hash;
    let cut = Position::new(U64::new(20), U64::new(0), Phase::Delivery);
    let old = json!({"owner":"owner","incarnation":"old","generation":"1"});
    let current = json!({"owner":"owner","incarnation":"fresh","generation":"2"});
    let value = json!({
        "schema":schema,"source_state":source,
        "source_ack":{"node":"node","owners":[old],"batch":"batch",
            "stage_operation":"stage","inventory":inventory,"cutoff":cut,"proof_ref":proof},
        "target":{"generation":"2","activation_id":"target","world_binding_hash":world,
            "owners":[current.clone()],"boundary":cut},
        "node":"node","owners":[current],"batch":"batch","stage_operation":"stage",
        "inventory":inventory,"cutoff":cut
    });
    let bytes = canonical::canonical_json(&value).map_err(invalid)?;
    let reference = canonical::content_ref(&bytes, "application/json").map_err(invalid)?;
    Ok(InputPayload { reference, bytes })
}

#[test]
fn selected_input_receipt_retains_all_positive_full_reference_roles() -> Result<(), TranscriptError>
{
    for schema in [
        "crucible.transcript-replay.input-admission.v1",
        "crucible.transcript-replay.input-custody.v1",
    ] {
        let object = receipt(schema)?;
        let roles = replay_input_custody_references(&object, object.bytes.len())?;
        assert_eq!(
            roles.source_state,
            canonical::content_ref(b"signed source data", "application/json").map_err(invalid)?
        );
        assert_eq!(
            roles.source_acknowledgement,
            canonical::content_ref(b"original ACK data", "application/json").map_err(invalid)?
        );
        assert_eq!(
            roles.inventory,
            canonical::content_ref(b"original ordered input data", "application/json")
                .map_err(invalid)?
        );
    }
    Ok(())
}

#[test]
fn input_receipt_refuses_budget_schema_and_changed_content() -> Result<(), TranscriptError> {
    let mut object = receipt("crucible.transcript-replay.input-admission.v1")?;
    assert!(replay_input_custody_references(&object, object.bytes.len() - 1).is_err());
    let unsupported = receipt("unsupported")?;
    assert!(replay_input_custody_references(&unsupported, MAXIMUM_STATE_BYTES).is_err());
    object.bytes.push(b' ');
    assert!(replay_input_custody_references(&object, MAXIMUM_STATE_BYTES).is_err());
    object.reference =
        canonical::content_ref(&object.bytes, "application/json").map_err(invalid)?;
    assert!(replay_input_custody_references(&object, MAXIMUM_STATE_BYTES).is_err());
    Ok(())
}

#[test]
fn input_receipt_refuses_foreign_identity_and_open_body() -> Result<(), TranscriptError> {
    let original = receipt("crucible.transcript-replay.input-admission.v1")?;
    for (field, value) in [("batch", json!("foreign")), ("undeclared", json!(null))] {
        let mut body =
            canonical::parse_json(&original.bytes, MAXIMUM_STATE_BYTES).map_err(invalid)?;
        body[field] = value;
        let bytes = canonical::canonical_json(&body).map_err(invalid)?;
        let reference = canonical::content_ref(&bytes, "application/json").map_err(invalid)?;
        assert!(
            replay_input_custody_references(
                &InputPayload { reference, bytes },
                MAXIMUM_STATE_BYTES
            )
            .is_err()
        );
    }
    Ok(())
}
