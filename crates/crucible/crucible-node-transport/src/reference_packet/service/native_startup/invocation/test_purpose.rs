//! Builds unchanged inert purpose fixtures through the actual public DATA reader.

use super::*;
use crucible_node_format::{ContentRef, U64, canonical};
use serde_json::{Value, json};

fn target() -> Result<Value, ProviderError> {
    Ok(json!({
        "world":canonical::hash("cnp.world-binding.v1",b"original")?,
        "binding":canonical::hash("cnp.node-binding.v1",b"original")?,
        "node":"node","owner":"owner","session":"session","incarnation":"incarnation",
        "owner_generation":U64::new(2),"prepared_token":"prepared","admission":"admission"
    }))
}

pub(super) fn original() -> Result<PacketNativeInvocationPurposeData, ProviderError> {
    PacketNativeInvocationPurposeData::from_original_value_data(&json!({
        "schema":"source-owned.packet-native-invocation-purpose/1",
        "purpose":"original_execution","source":null,"target":target()?
    }))
}

pub(super) fn restoration(
    runtime: &ContentRef,
    native: &ContentRef,
) -> Result<PacketNativeInvocationPurposeData, ProviderError> {
    PacketNativeInvocationPurposeData::from_original_value_data(&json!({
        "schema":"source-owned.packet-native-invocation-purpose/1",
        "purpose":"restoration_target",
        "source":{"runtime":runtime,"native_state":native,"owner":"owner"},
        "target":target()?
    }))
}

#[test]
fn projected_original_target_uses_the_same_actual_control_and_refuses_foreign_rosters()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, _, mut selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let purpose = PacketNativeInvocationPurposeData::original_execution_control_data(&selection)?;
    purpose.authenticate_control_target_data(&selection)?;
    assert!(purpose.is_original_execution_data());

    let value = serde_json::to_value(purpose)?;
    assert_eq!(
        value["target"]["prepared_token"],
        serde_json::to_value(&selection.prepared_token)?
    );
    assert_eq!(
        value["target"]["admission"],
        serde_json::to_value(&selection.admission)?
    );
    assert_eq!(
        value["target"]["world"],
        serde_json::to_value(&selection.world)?
    );
    assert!(value["source"].is_null());

    selection.prepared_token = crucible_node_format::Id::new("foreign-prepared")?;
    assert!(
        purpose
            .authenticate_control_target_data(&selection)
            .is_err()
    );
    selection.realization.bindings.clear();
    assert!(
        PacketNativeInvocationPurposeData::original_execution_control_data(&selection).is_err()
    );
    Ok(())
}
