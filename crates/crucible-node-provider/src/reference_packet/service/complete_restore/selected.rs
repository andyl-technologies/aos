//! Enumerates each explicitly selected restore grammar before tuple hashing.
//!
//! The roster is declaration data. It cannot accept an upload, verify a key,
//! enroll a historical actor or authorize the mechanical installer.

use super::transfer::{
    PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE, PacketCompleteRestoreTransferPhase as Phase,
    PacketCompleteRestoreTransferSchema as Kind, complete_restore_transfer_contract,
    complete_restore_transfer_schema,
};
use super::*;
use crate::reference_packet::service::complete_restore::{
    PACKET_NATIVE_RESTORED_RECORD_FEATURE, native_restored_record_contract,
    native_restored_record_schema,
};

/// Enumerates the full fixed schema roster selected before native birth.
///
/// The transfer edition retains the original three definitions and adds exactly
/// six phase definitions plus the restored native content grammar. Both selected
/// editions retain the exact raw-before native snapshot definition. No unknown
/// schema is treated as a leaf or silently accepted.
///
/// # Errors
/// Refuses failure to encode any source-authored fixed schema definition.
pub fn complete_restore_selected_schemas(
    selection: PacketNative5CompleteRestoreSelection,
) -> Result<Vec<SchemaRef>, ProviderError> {
    let mut schemas = vec![
        complete_restore_request_schema()?,
        complete_restore_proof_schema()?,
        complete_restore_receipt_schema()?,
    ];
    if selection == PacketNative5CompleteRestoreSelection::SourceSignedTransfer12 {
        for phase in [Phase::Prepare, Phase::Commit] {
            for kind in [Kind::Request, Kind::Proof, Kind::Receipt] {
                schemas.push(complete_restore_transfer_schema(phase, kind)?);
            }
        }
        schemas.push(native_restored_record_schema()?);
    }
    schemas.push(crate::reference_packet::service::native_owned11_snapshot_schema()?);
    Ok(schemas)
}

/// Enumerates full fixed bodies matching the selected schema roster exactly.
///
/// # Errors
/// Refuses encoding failure or any full definition reference/body mismatch.
pub fn complete_restore_selected_contracts(
    selection: PacketNative5CompleteRestoreSelection,
) -> Result<Vec<(SchemaRef, Vec<u8>)>, ProviderError> {
    let schemas = complete_restore_selected_schemas(selection)?;
    let mut bodies = Vec::with_capacity(schemas.len());
    for (index, schema) in schemas.into_iter().enumerate() {
        let snapshot = crate::reference_packet::service::native_owned11_snapshot_schema()?;
        let body = if schema == snapshot {
            crate::reference_packet::service::native_owned11_snapshot_contract()?
        } else {
            match index {
                0..=2 => complete_restore_contract()?,
                3..=8 => complete_restore_transfer_contract()?,
                9 => native_restored_record_contract()?,
                _ => {
                    return Err(ProviderError::Correlation(
                        "closed restore schema roster exceeded",
                    ));
                }
            }
        };
        schema.definition.verify(&body)?;
        bodies.push((schema, body));
    }
    Ok(bodies)
}

/// Enumerates exact negotiated envelope keys for the selected restore route.
///
/// The transfer and restored-content features themselves are not envelope keys.
pub fn complete_restore_selected_envelope_extensions(
    selection: PacketNative5CompleteRestoreSelection,
) -> Vec<&'static str> {
    let mut keys = vec![
        PACKET_COMPLETE_RESTORE_FEATURE,
        PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
        PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
    ];
    if selection == PacketNative5CompleteRestoreSelection::SourceSignedTransfer12 {
        for phase in [Phase::Prepare, Phase::Commit] {
            keys.extend([
                phase.request_extension(),
                phase.proof_extension(),
                phase.receipt_extension(),
            ]);
        }
    }
    keys
}

/// Enumerates exact features independently of envelope extension negotiation.
pub fn complete_restore_selected_features(
    selection: PacketNative5CompleteRestoreSelection,
) -> Vec<&'static str> {
    let mut features = complete_restore_selected_envelope_extensions(selection);
    if selection == PacketNative5CompleteRestoreSelection::SourceSignedTransfer12 {
        features.extend([
            PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE,
            PACKET_NATIVE_RESTORED_RECORD_FEATURE,
        ]);
    }
    features
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn selected_roster_preserves_original_definitions_and_separates_content_features() {
        let original = complete_restore_selected_contracts(
            PacketNative5CompleteRestoreSelection::SourceSignedOwned11,
        )
        .unwrap();
        let selected = complete_restore_selected_contracts(
            PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
        )
        .unwrap();
        assert_eq!(original.len(), 4);
        assert_eq!(selected.len(), 11);
        assert_eq!(original[..3], selected[..3]);
        assert_eq!(original.last(), selected.last());
        assert_eq!(
            original.last().unwrap().0,
            crate::reference_packet::service::native_owned11_snapshot_schema().unwrap()
        );
        for (schema, bytes) in &selected {
            schema.definition.verify(bytes).unwrap();
        }
        let selection = PacketNative5CompleteRestoreSelection::SourceSignedTransfer12;
        let features = complete_restore_selected_features(selection);
        let extensions = complete_restore_selected_envelope_extensions(selection);
        assert!(features.contains(&PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE));
        assert!(features.contains(&PACKET_NATIVE_RESTORED_RECORD_FEATURE));
        assert!(!extensions.contains(&PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE));
        assert!(!extensions.contains(&PACKET_NATIVE_RESTORED_RECORD_FEATURE));
        assert_eq!(extensions.len(), 9);
    }
}
