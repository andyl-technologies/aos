//! Declares the separate complete restored-state capture family.
//!
//! The full immutable definition is installation DATA. Selecting it does not
//! create a Capture ticket, current World, spending ledger or restore right.
//! Old invocation snapshots retain their original formats and refusal guards.
//!
//! ```text
//! schema: source-owned.packet-restored-settled-recapture/1
//! native: source-private.native-state/17
//! host: source-private.host-state-restored-settled/17
//! semantic: source-private.semantic-state-restored-settled/17
//! ```

use crate::ProviderError;
use crucible_node_format::{Id, SchemaRef, canonical};

#[path = "settled_recapture/selection.rs"]
mod selection;
pub use selection::{
    authenticate_restored_settled_capture_immutable_declaration_data,
    authenticate_restored_settled_capture_selection_data,
    restored_settled_capture_selection_counter_scratch_data,
};

#[path = "settled_recapture/output_limits.rs"]
mod output_limits;
pub use output_limits::PacketRestoredSettledCaptureOutputLimits;

/// Names the separately selected complete settled-recapture declaration.
pub const PACKET_RESTORED_SETTLED_RECAPTURE_FEATURE: &str =
    "source-owned.packet-restored-settled-recapture/1";

/// Names the full native snapshot carried by the settled family.
pub const PACKET_RESTORED_SETTLED_NATIVE_SNAPSHOT: &str =
    "source-owned.packet-native-continuation/17";

/// Names the complete historical host component without live SDK authority.
pub const PACKET_RESTORED_SETTLED_HOST_FORMAT: &str =
    "source-private.host-state-restored-settled/17";

/// Names immutable first ancestry beside independent current semantic custody.
pub const PACKET_RESTORED_SETTLED_SEMANTIC_FORMAT: &str =
    "source-private.semantic-state-restored-settled/17";

const CONTRACT: &[u8] = include_bytes!("settled_recapture/contract.json");

/// Borrows the exact full definition without its source-file newline.
pub fn restored_settled_recapture_contract_data() -> &'static [u8] {
    CONTRACT.strip_suffix(b"\n").unwrap_or(CONTRACT)
}

/// Returns the full immutable declaration for explicit installation selection.
///
/// # Errors
/// Reports invalid compiled identifiers or ContentRef construction failure.
pub fn restored_settled_recapture_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(PACKET_RESTORED_SETTLED_RECAPTURE_FEATURE)?,
        version: 1,
        definition: canonical::content_ref(
            restored_settled_recapture_contract_data(),
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

/// Compares the complete declaration using fixed hash scratch only.
///
/// This comparison authenticates DATA identity. The caller must separately
/// authenticate its actual original issuer, current scope and admitted work.
///
/// # Errors
/// Refuses another identifier, version, full definition or schema extension.
pub fn authenticate_restored_settled_recapture_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    let bytes = restored_settled_recapture_contract_data();
    let length = u64::try_from(bytes.len()).map_err(|_| invalid())?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&length.to_be_bytes());
    hash.update(bytes);
    let digest = hash.finalize().to_hex();

    if schema.id.as_str() != PACKET_RESTORED_SETTLED_RECAPTURE_FEATURE
        || schema.version != 1
        || !schema.extensions.is_empty()
        || schema.definition.hash.algorithm != "blake3-256"
        || schema.definition.hash.domain != "cnp.blob.v1"
        || schema.definition.hash.digest != digest.as_str()
        || schema.definition.length.get() != length
        || schema.definition.media_type != "application/json"
    {
        return Err(invalid());
    }

    Ok(())
}

/// Names the exact fixed declaration comparison and borrowed/result views.
pub fn restored_settled_recapture_schema_counter_scratch_data() -> usize {
    use std::mem::size_of;

    size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<&SchemaRef>()
        + size_of::<&[u8]>()
        + size_of::<Option<&[u8]>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + std::mem::size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
}

/// Returns the exact immutable capability definitions before implementation hashing.
///
/// The caller retains the resulting full SchemaRefs and admits its real output
/// owners. These bodies may be advertised by Original15 without selecting a
/// target17 startup, decoder, native reserve or Capture right.
///
/// # Errors
/// Reports invalid compiled schema identifiers or content-reference construction.
pub fn restored_settled_capture_declared_contracts_data()
-> Result<impl ExactSizeIterator<Item = (SchemaRef, &'static [u8])>, ProviderError> {
    use crate::reference_packet::service::{
        native_snapshot, restored_input_reactive17 as input, restored_settled_capture as capture,
        restored_settled_confirmation as confirmation,
    };
    Ok([
        (
            restored_settled_recapture_schema()?,
            restored_settled_recapture_contract_data()
        ),
        (
            native_snapshot::native_restored_settled17_snapshot_schema()?,
            native_snapshot::native_restored_settled17_snapshot_contract_data()
        ),
        (
            capture::restored_settled_capture_schema_data()?,
            capture::restored_settled_capture_contract_data()
        ),
        (
            capture::upload::restored_settled_capture_upload_schema_data()?,
            capture::upload::restored_settled_capture_upload_contract_data()
        ),
        (
            confirmation::restored_settled_after_confirmation_schema_data()?,
            confirmation::restored_settled_after_confirmation_contract_bytes_data()
        ),
        (
            crate::reference_packet::service::native_startup::restored_settled_startup_schema_data()?,
            crate::reference_packet::service::native_startup::restored_settled_startup_contract_data()
        ),
        (
            coordinator_checkpoint17_schema_data()?,
            coordinator_checkpoint17_contract_data()
        ),
        (
            input::restored_input_reactive17_schema_data()?,
            input::restored_input_reactive17_contract_data()
        ),
    ]
    .into_iter())
}

/// Borrows every required capability feature without selecting a realization.
pub fn restored_settled_capture_declared_features_data() -> &'static [&'static str] {
    &selection::FEATURES
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored settled recapture declaration differs")
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These immutable DATA controls deliberately panic on failed fixture invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_format::U64;

    #[test]
    fn exact_eight_definitions_and_six_features_are_one_closed_declaration() {
        let formats: Vec<_> = restored_settled_capture_declared_contracts_data()
            .unwrap()
            .map(|(schema, _)| schema)
            .collect();
        let features: Vec<_> = restored_settled_capture_declared_features_data()
            .iter()
            .map(|name| Id::new(*name).unwrap())
            .collect();
        assert_eq!(formats.len(), 8);
        assert_eq!(features.len(), 6);
        authenticate_restored_settled_capture_immutable_declaration_data(
            &formats, &formats, &features,
        )
        .unwrap();
        for index in 0..formats.len() {
            let mut missing = formats.clone();
            missing.remove(index);
            assert!(
                authenticate_restored_settled_capture_immutable_declaration_data(
                    &missing, &formats, &features
                )
                .is_err()
            );
            assert!(
                authenticate_restored_settled_capture_immutable_declaration_data(
                    &formats, &missing, &features
                )
                .is_err()
            );
            let mut changed = formats.clone();
            changed[index].definition.hash.digest = "0".repeat(64);
            assert!(
                authenticate_restored_settled_capture_immutable_declaration_data(
                    &changed, &formats, &features
                )
                .is_err()
            );
        }
        for index in 0..features.len() {
            let mut missing = features.clone();
            missing.remove(index);
            assert!(
                authenticate_restored_settled_capture_immutable_declaration_data(
                    &formats, &formats, &missing
                )
                .is_err()
            );
        }
    }

    #[test]
    fn full_definition_comparison_rejects_each_substituted_identity_axis() {
        let original = restored_settled_recapture_schema().unwrap();
        authenticate_restored_settled_recapture_schema_data(&original).unwrap();
        let value = canonical::parse_json(
            restored_settled_recapture_contract_data(),
            restored_settled_recapture_contract_data().len(),
        )
        .unwrap();
        assert_eq!(
            canonical::canonical_json(&value).unwrap(),
            restored_settled_recapture_contract_data()
        );

        for axis in 0..8 {
            let mut changed = original.clone();
            match axis {
                0 => changed.id = Id::new("source-owned.packet-restored-suffix/1").unwrap(),
                1 => changed.version = 17,
                2 => changed.definition.hash.algorithm = "sha256".into(),
                3 => changed.definition.hash.domain = "another-domain".into(),
                4 => changed.definition.hash.digest = "0".repeat(64),
                5 => {
                    changed.definition.length =
                        U64::new(changed.definition.length.get().checked_add(1).unwrap());
                }
                6 => changed.definition.media_type = "application/octet-stream".into(),
                _ => {
                    changed
                        .extensions
                        .insert("unknown".into(), serde_json::Value::Bool(true));
                }
            }
            assert!(authenticate_restored_settled_recapture_schema_data(&changed).is_err());
        }
    }
}

mod checkpoint_schema;

pub use checkpoint_schema::{
    COORDINATOR_CHECKPOINT17_MEDIA, COORDINATOR_CHECKPOINT17_SCHEMA,
    authenticate_coordinator_checkpoint17_schema_data, coordinator_checkpoint17_contract_data,
    coordinator_checkpoint17_schema_counter_scratch_data, coordinator_checkpoint17_schema_data,
};

/// Names the enclosing current17 Input and Reactive semantic support capability.
///
/// The separately negotiated assigned-request proof uses
/// `restored_input_reactive17::RESTORED_INPUT_REACTIVE17_FEATURE`. Neither
/// capability is an alias or an alternative parser for the other.
pub const PACKET_RESTORED_SETTLED_INPUT_REACTIVE_FEATURE: &str =
    "source-owned.packet-restored-settled-input-reactive/17";

#[path = "settled_recapture/checkpoint.rs"]
mod checkpoint;
pub use checkpoint::{
    CoordinatorCheckpointStorageData17, CoordinatorCommitmentActivation17,
    CoordinatorCommitmentCheckpoint17, CoordinatorCommitmentEntry17, CoordinatorCommitmentKind17,
    CoordinatorCommitmentSafePoint17, CoordinatorCommitmentState17,
};
