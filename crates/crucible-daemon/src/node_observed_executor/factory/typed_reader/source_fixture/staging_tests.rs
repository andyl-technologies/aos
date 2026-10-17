//! Checks source-derived native ACK encoding and complete envelope credit.

use super::{AcknowledgementView, invalid};
use crucible::node_scheduling::NativeInputAcknowledgement;
use crucible_node_contract::{Id, Phase, Position, U64, canonical};
use crucible_node_provider::ProviderError;

#[test]
fn borrowed_native_ack_matches_complete_original_codec_and_keeps_root() -> Result<(), ProviderError>
{
    let root = canonical::content_ref(b"original-source-ack", "application/json")?;
    let inventory = canonical::content_ref(b"[]", "application/json")?;
    let original = NativeInputAcknowledgement {
        stage_operation: Id::new("original/stage")?,
        batch: Id::new("original/batch")?,
        node: Id::new("original/node")?,
        owners: Vec::new(),
        cutoff: Position::new(U64::new(1001), U64::new(0), Phase::BoundaryControl),
        inventory,
        proof_ref: root,
    };
    let view = AcknowledgementView {
        stage_operation: &original.stage_operation,
        batch: &original.batch,
        node: &original.node,
        owners: &original.owners,
        cutoff: original.cutoff,
        inventory: &original.inventory,
        proof_ref: &original.proof_ref,
    };
    let encoded = super::super::launch::encode(&view, 65536)?;
    assert_eq!(encoded, super::super::launch::encode(&original, 65536)?);
    let changed = AcknowledgementView {
        cutoff: Position::new(U64::new(1002), U64::new(0), Phase::BoundaryControl),
        ..view
    };
    assert_ne!(encoded, super::super::launch::encode(&changed, 65536)?);
    Ok(())
}

#[test]
fn complete_source_envelope_charges_each_original_body_occurrence() -> Result<(), ProviderError> {
    let body = "original-body".repeat(32);
    let whole = (&body, &body, &body);
    let single = super::super::launch::encode(&body, 65536)?;
    let encoded = super::super::launch::encode(&whole, 65536)?;
    assert!(encoded.len() > single.len() * 2);
    assert!(super::super::launch::encode(&whole, single.len() * 2).is_err());
    assert_eq!(
        encoded,
        super::super::launch::encode(&whole, encoded.len())?
    );
    let lower = encoded.len().checked_sub(1).ok_or_else(invalid)?;
    assert!(super::super::launch::encode(&whole, lower).is_err());
    Ok(())
}
