//! Defines the separate settled-Capture fourth-object confirmation grammar.
//!
//! ```text
//! Poll.extensions[feature17] = request17
//! PollReply.extensions[feature17] = {schema, capture:request17,
//!                                   native_after_ref,native_after_capacity}
//! ```
//!
//! The actual selected native Capture permit, its retained assigned request and
//! terminal, three transferred objects and Source currentness remain separate
//! prerequisites. These closed DTOs cannot grant Capture or produce an after owner.

use crate::ProviderError;
use crucible_node_format::{ContentRef, HashRef, Id, SchemaRef, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

/// Names the distinct request/response extension for the fourth actual object.
pub const PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE: &str =
    "source-owned.packet-native-after-restored-settled-confirmation/17";
/// Names the exact closed confirmation request grammar.
pub const PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA: &str =
    "source-owned.packet-native-after-restored-settled-confirmation-request/17";
/// Names the exact closed confirmation receipt grammar.
pub const PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_RECEIPT_SCHEMA: &str =
    "source-owned.packet-native-after-restored-settled-confirmation-receipt/17";
/// Separates complete final Capture terminal hashes from original-purpose hashes.
pub const PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN: &str =
    "source-owned.packet-native-restored-settled-capture-terminal/17";

/// Binds a fourth-object query to the actual proof-filled settled Capture.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledAfterConfirmationRequest {
    /// Selects only this new closed request family.
    pub schema: String,
    /// Names the real retained Capture original in both endpoint journals.
    pub capture_request_id: Id,
    /// Commits to its normative original request identity.
    pub capture_request_hash: HashRef,
    /// Names that same original Capture operation.
    pub capture_operation_id: Id,
    /// Commits to its complete final canonical terminal under the new domain.
    pub capture_terminal_hash: HashRef,
    /// Retains its actual post-transfer provider sequence.
    pub capture_terminal_sequence: U64,
    /// Names the actual complete proof-filled Capture Envelope canonical bytes.
    pub settled_capture_request: ContentRef,
    /// Names the actual transferred whole native snapshot.
    pub native_snapshot_ref: ContentRef,
    /// Names the actual separately transferred Control snapshot.
    pub native_control_ref: ContentRef,
    /// Names the actual separately transferred unchanged-cut anchor.
    pub native_anchor_ref: ContentRef,
}

/// Binds the actual fourth native body and its independent retained capacity.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledAfterConfirmationReceipt {
    /// Selects only the new closed receipt grammar.
    pub schema: String,
    /// Retains the exact actual confirmation request conjunction.
    pub capture: PacketRestoredSettledAfterConfirmationRequest,
    /// Names the immutable fourth body transferred before the Poll terminal.
    pub native_after_ref: ContentRef,
    /// Reports its real independent byte-bank capacity for separate accounting.
    pub native_after_capacity: U64,
}

impl crate::retained_metadata::ObserveMetadata for PacketRestoredSettledAfterConfirmationRequest {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            capture_request_id,
            capture_request_hash,
            capture_operation_id,
            capture_terminal_hash,
            capture_terminal_sequence,
            settled_capture_request,
            native_snapshot_ref,
            native_control_ref,
            native_anchor_ref,
        } = self;
        observer.observe(schema)?;
        observer.observe(capture_request_id)?;
        observer.observe(capture_request_hash)?;
        observer.observe(capture_operation_id)?;
        observer.observe(capture_terminal_hash)?;
        observer.observe(capture_terminal_sequence)?;
        observer.observe(settled_capture_request)?;
        observer.observe(native_snapshot_ref)?;
        observer.observe(native_control_ref)?;
        observer.observe(native_anchor_ref)
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketRestoredSettledAfterConfirmationReceipt {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            capture,
            native_after_ref,
            native_after_capacity,
        } = self;
        observer.observe(schema)?;
        observer.observe(capture)?;
        observer.observe(native_after_ref)?;
        observer.observe(native_after_capacity)
    }
}

impl PacketRestoredSettledAfterConfirmationRequest {
    /// Validates the closed grammar without authenticating an original or permit.
    ///
    /// # Errors
    /// Refuses a wrong family/domain, invalid identifier or full reference, absent
    /// terminal sequence, non-JSON request object or aliased native object tuple.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.capture_request_id.validate()?;
        self.capture_operation_id.validate()?;
        self.capture_request_hash.validate()?;
        self.capture_terminal_hash.validate()?;
        self.settled_capture_request.validate()?;
        self.native_snapshot_ref.validate()?;
        self.native_control_ref.validate()?;
        self.native_anchor_ref.validate()?;

        if self.schema != PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA
            || self.capture_request_hash.domain != "cnp.request.v1"
            || self.capture_terminal_hash.domain != PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN
            || self.capture_terminal_sequence.get() == 0
            || self.settled_capture_request.media_type != "application/json"
            || self.native_snapshot_ref == self.native_control_ref
            || self.native_snapshot_ref == self.native_anchor_ref
            || self.native_control_ref == self.native_anchor_ref
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl PacketRestoredSettledAfterConfirmationReceipt {
    /// Validates a closed fourth-body receipt without granting fresh adoption.
    ///
    /// # Errors
    /// Refuses malformed request data, another family, invalid after reference,
    /// insufficient retained capacity or aliasing with an earlier native object.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.capture.validate_data()?;
        self.native_after_ref.validate()?;
        if self.schema != PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_RECEIPT_SCHEMA
            || self.native_after_capacity.get() < self.native_after_ref.length.get()
            || self.native_after_ref == self.capture.native_snapshot_ref
            || self.native_after_ref == self.capture.native_control_ref
            || self.native_after_ref == self.capture.native_anchor_ref
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Encodes the immutable complete selected17 confirmation definition.
///
/// # Errors
/// Refuses canonical encoding failure; returned bytes are not an installation.
pub fn restored_settled_after_confirmation_contract_data() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(ConfirmationContract)
            .map_err(crucible_node_format::ContractError::from)?,
    )?)
}

/// Returns the full schema reference to the same immutable compiled definition.
///
/// # Errors
/// Refuses canonical definition encoding or invalid schema identity.
pub fn restored_settled_after_confirmation_schema_data() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE)?,
        version: 17,
        definition: canonical::content_ref(
            &restored_settled_after_confirmation_contract_data()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

struct ConfirmationContract;

impl Serialize for ConfirmationContract {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text(
                    "source-owned.packet-native-after-restored-settled-confirmation-contract/17",
                ),
            ),
            (
                "feature",
                V::Text(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE),
            ),
            (
                "request_schema",
                V::Text(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA),
            ),
            (
                "receipt_schema",
                V::Text(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_RECEIPT_SCHEMA),
            ),
            (
                "terminal_domain",
                V::Text(PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN),
            ),
            (
                "request_fields",
                V::Array(&[
                    V::Text("schema:String"),
                    V::Text("capture_request_id:Id"),
                    V::Text("capture_request_hash:HashRef(cnp.request.v1)"),
                    V::Text("capture_operation_id:Id"),
                    V::Text("capture_terminal_hash:HashRef(terminal_domain)"),
                    V::Text("capture_terminal_sequence:U64(nonzero)"),
                    V::Text("settled_capture_request:ContentRef(application/json)"),
                    V::Text("native_snapshot_ref:ContentRef"),
                    V::Text("native_control_ref:ContentRef"),
                    V::Text("native_anchor_ref:ContentRef"),
                ]),
            ),
            (
                "receipt_fields",
                V::Array(&[
                    V::Text("schema:String"),
                    V::Text("capture:request_schema"),
                    V::Text("native_after_ref:ContentRef"),
                    V::Text("native_after_capacity:U64"),
                ]),
            ),
            ("closed", V::Text("deny_unknown_fields")),
            (
                "ordering",
                V::Text(
                    "actual selected Capture permit and proof-filled assigned original; exact three transferred objects and their ACKs before Capture terminal; actual fourth after body then all ACKs before final correlated Poll terminal",
                ),
            ),
            (
                "history",
                V::Text(
                    "prefix freezes before this Capture auxiliary uploads; Capture, uploads, terminal, confirmation and fourth-body ACK suffix retained independently and never replayed as execution",
                ),
            ),
            (
                "authority",
                V::Text(
                    "syntax/full hashes/receipt/capacity are DATA; genuine ticket, current Source/Window, actual native spent permit and independently admitted all-owner row remain mandatory",
                ),
            ),
        ]);
        VALUE.serialize(serializer)
    }
}

/// Quotes the same compiled definition without a second guessed schema roster.
///
/// # Errors
/// Refuses checked extent overflow or complete definition demand above policy.
pub fn restored_settled_after_confirmation_contract_storage_data(
    maximum: usize,
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ProviderError,
> {
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &ConfirmationContract,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

/// Names fixed DTO, validation and canonical construction result views.
pub fn restored_settled_after_confirmation_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<PacketRestoredSettledAfterConfirmationRequest>()
        + size_of::<PacketRestoredSettledAfterConfirmationReceipt>()
        + size_of::<ConfirmationContract>()
        + size_of::<&PacketRestoredSettledAfterConfirmationRequest>()
        + size_of::<&PacketRestoredSettledAfterConfirmationReceipt>()
        + size_of::<&ContentRef>() * 4
        + size_of::<&HashRef>() * 2
        + size_of::<&Id>() * 2
        + size_of::<Result<(), ProviderError>>()
        + size_of::<serde_json::Value>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<SchemaRef>()
        + size_of::<Result<SchemaRef, ProviderError>>()
        + size_of::<Result<Id, crucible_node_format::ContractError>>()
        + size_of::<Result<ContentRef, crucible_node_format::ContractError>>()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>(
        )
        + size_of::<
            Result<
                crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
                ProviderError,
            >,
        >()
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("settled Capture fourth-object confirmation grammar differs")
}

#[cfg(test)]
mod tests {
    use super::*;

    // These closed DTOs test syntax only; no Source/native owner is constructed.
    fn request() -> PacketRestoredSettledAfterConfirmationRequest {
        let reference =
            |name: &str| canonical::content_ref(name.as_bytes(), "application/json").unwrap();
        PacketRestoredSettledAfterConfirmationRequest {
            schema: PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA.into(),
            capture_request_id: Id::new("settled-capture-original").unwrap(),
            capture_request_hash: canonical::hash("cnp.request.v1", b"actual-request-DATA")
                .unwrap(),
            capture_operation_id: Id::new("settled-capture-operation").unwrap(),
            capture_terminal_hash: canonical::hash(
                PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN,
                b"terminal-DATA",
            )
            .unwrap(),
            capture_terminal_sequence: U64::new(31),
            settled_capture_request: reference("proof-filled-request-DATA"),
            native_snapshot_ref: reference("snapshot-DATA"),
            native_control_ref: reference("control-DATA"),
            native_anchor_ref: reference("anchor-DATA"),
        }
    }

    #[test]
    fn settled_confirmation_rejects_old_family_and_terminal_domain() {
        let mut original = request();
        original.validate_data().unwrap();
        original.schema = "source-owned.packet-native-after-confirmation-request/5".into();
        assert!(original.validate_data().is_err());

        original.schema = PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA.into();
        original.capture_terminal_hash = canonical::hash(
            "source-owned.packet-native-capture-terminal/5",
            b"terminal-DATA",
        )
        .unwrap();
        assert!(original.validate_data().is_err());

        let mut value = serde_json::to_value(request()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unrecognized".into(), serde_json::Value::Null);
        assert!(
            serde_json::from_value::<PacketRestoredSettledAfterConfirmationRequest>(value).is_err()
        );
    }

    #[test]
    fn settled_confirmation_keeps_full_request_and_independent_fourth_extent() {
        let body = b"fourth-native-body-DATA";
        let mut receipt = PacketRestoredSettledAfterConfirmationReceipt {
            schema: PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_RECEIPT_SCHEMA.into(),
            capture: request(),
            native_after_ref: canonical::content_ref(body, "application/json").unwrap(),
            native_after_capacity: U64::new(body.len() as u64),
        };
        receipt.validate_data().unwrap();
        let encoded = serde_json::to_value(&receipt).unwrap();
        let decoded: PacketRestoredSettledAfterConfirmationReceipt =
            serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, receipt);
        receipt.native_after_capacity = U64::new(body.len() as u64 - 1);
        assert!(receipt.validate_data().is_err());

        receipt.native_after_capacity = U64::new(body.len() as u64);
        receipt.native_after_ref = receipt.capture.native_control_ref.clone();
        assert!(receipt.validate_data().is_err());

        let schema = restored_settled_after_confirmation_schema_data().unwrap();
        assert_eq!(schema.version, 17);
        schema
            .definition
            .verify(&restored_settled_after_confirmation_contract_data().unwrap())
            .unwrap();
    }
}

const COMPILED_DEFINITION: &[u8] = include_bytes!("restored_settled_confirmation.json");

/// Borrows the exact canonical definition without its source-file newline.
pub fn restored_settled_after_confirmation_contract_bytes_data() -> &'static [u8] {
    COMPILED_DEFINITION
        .strip_suffix(b"\n")
        .unwrap_or(COMPILED_DEFINITION)
}

/// Compares every full schema field without allocating definition/identifier data.
///
/// This hash view grants neither immutable Source selection nor installation.
///
/// # Errors
/// Refuses another ID/version/definition/media type/extensions or length overflow.
pub fn authenticate_restored_settled_after_confirmation_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    let bytes = restored_settled_after_confirmation_contract_bytes_data();
    let length = u64::try_from(bytes.len()).map_err(|_| invalid())?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&length.to_be_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize().to_hex();
    if schema.id.as_str() != PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE
        || schema.version != 17
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

/// Names the complete fixed borrowed comparison and compiled-hash views.
pub fn restored_settled_after_confirmation_schema_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + std::mem::size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
        + size_of::<&SchemaRef>()
        + size_of::<&[u8]>()
        + size_of::<Option<&[u8]>>()
        + size_of::<u64>()
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
}

#[cfg(test)]
mod schema_correspondence_tests {
    use super::*;

    #[test]
    fn settled_confirmation_fixed_definition_matches_actual_factory_and_full_schema() {
        let bytes = restored_settled_after_confirmation_contract_data().unwrap();
        assert_eq!(
            restored_settled_after_confirmation_contract_bytes_data(),
            bytes
        );
        let mut schema = restored_settled_after_confirmation_schema_data().unwrap();
        authenticate_restored_settled_after_confirmation_schema_data(&schema).unwrap();

        schema.definition =
            canonical::content_ref(b"other-full-definition", "application/json").unwrap();
        assert!(authenticate_restored_settled_after_confirmation_schema_data(&schema).is_err());
        schema = restored_settled_after_confirmation_schema_data().unwrap();
        schema.version = 5;
        assert!(authenticate_restored_settled_after_confirmation_schema_data(&schema).is_err());
        schema = restored_settled_after_confirmation_schema_data().unwrap();
        schema
            .extensions
            .insert("foreign".into(), serde_json::Value::Null);
        assert!(authenticate_restored_settled_after_confirmation_schema_data(&schema).is_err());
    }
}
